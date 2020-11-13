#include <pcap.h>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include "inc/common.hpp"
#include "link/getaddr.hpp"
#include "link/device.hpp"
#include "link/device_internal.hpp"
#include "link/ethernet.hpp"
#include "link/compose.hpp"
#include "ip.hpp"
#include "routing.hpp"

std::vector<int> scanAllDevices(const char *startsWith) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "[IP Error] pcap_findalldevs error: %s\n", errbuf);
        return std::vector<int>(); // empty
    }
    std::vector<int> ret;
    for(pcap_if_t *it = interfaces; it; it = it->next) {
        if(startsWith) {
            bool mismatch = false;
            for(int i = 0; startsWith[i]; ++i) if(it->name[i] != startsWith[i]) {
                    mismatch = true;
                    break;
                }
            if(mismatch) continue;
        }
        int id = addDevice(it->name);
        if(id != -1) ret.push_back(id);
    }
    pcap_freealldevs(interfaces);
    return ret;
}

static IPPacketReceiveCallback ip_callback;

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    ip_callback = callback;
    return 0;
}

// compute the header checksum using one's complement
// as RFC 1071 states, by using one's complement, we can compute
// this checksum independent of host byte order.
static uint16_t computeIPHeaderChecksum(const void *buf) {
    uint8_t signature = *(const uint8_t *)buf;
    uint8_t hdlen = signature & 15;
    if(hdlen < 5) return -1;
    const uint16_t *buf16 = (const uint16_t *)buf;
    uint32_t sum = 0;
    for(int i = 0; i < hdlen * 2; ++i) sum += buf16[i];
    sum -= buf16[5];
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// sendIPPacket is called by frameCallback, and also by
// IP layer users through sendIPPacket.
// it either forward the IP packet according to routing table,
// or calling ip_callback if its destination is this host.
// IMPORTANT NOTICE:
// If called by IP layer users, you might like to make your ip_callback
// not only thread-safe, but REENTRANT.
// OTHERWISE, you should NEVER call sendIPPacket within a ip_callback.
static int forwardIPPacket(const void *buf, int len) {
    if(len < 20) {
        fprintf(stderr, "[IP Error] forwardIPPacket bad packet with len=%d\n", len);
        return -1;
    }
    uint8_t signature = *(const uint8_t *)buf;
    uint8_t version = signature >> 4;
    if(version != 4) {
        fprintf(stderr, "[IP Error] cannot forward IPv%u\n", (uint32_t)version);
        return -1;
    }
    ip_t dest = *(const ip_t *)((char *)buf + 16);
    std::optional<RoutingTableEntry> rte = queryRoutingTable(dest);
    if(rte) {
        if(rte->next_device_id == -1) {
            int cb_ret = ip_callback(buf, len);
            if(cb_ret < 0) {
                fprintf(stderr, "[IP Error] IP callback failed returning %d\n", cb_ret);
            }
            return 0;  // whether or not callback error, don't propagate error.
        }
        else {
            sendFrame(buf, len, ETHER_TYPE_IP, rte->next_hop_mac, rte->next_device_id);
            return 0;
        }
    }
    else {
        fprintf(stderr, "[IP Error] forwardIPPacket doesn't know where to "
                "forward %s. Dropping this.\n", ip2str(dest).c_str());
        return 0;     // I think this shouldn't be classified as a fatal
                      //  error for upstream. so just stop propagating error.
    }
}

// frameCallback is executed in capturing threads. It blocks the execution of exactly
// one capturing thread.
int frameCallback(const void *buf, int len, int id) {
    const mac_t broadcast_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    mac_t mac;
    memcpy(mac, getDeviceInfo(id)->mac, sizeof(mac_t));
    if(memcmp(buf, mac, 6) != 0 && memcmp(buf, broadcast_mac, 6) != 0) {
        // drop unintended packet
        return 0;
    }
    int ethtype = ((char *)buf)[12] << 8 | ((char *)buf)[13];
    if(ethtype == ETHER_TYPE_ROUTING) {
        onRoutingPacket((char *)buf + 14, len - 14, (uint8_t *)buf + 6, id);
        return 0;
    }
    else if(ethtype == ETHER_TYPE_IP) {
        // todo: only receive IPs correspond to our hosts, and forward other IPs.
        // todo: check header checksum
        return ip_callback((char *)buf + 14, len - 14);
    }
    else {
        fprintf(stderr, "Unrecognized ethtype: 0x%04x\n", ethtype);
        return 0;
    }
}

void startIPService(const std::vector<int> &interfaces) {
    std::thread t_announce(announceServiceWorker, interfaces);
    t_announce.detach();
    setFrameReceiveCallback(frameCallback);
    startComposedCapturing(interfaces);
    fprintf(stderr, "IP service started.\n");
}

int sendIPPacket(ip_t src, ip_t dest, 
                 int proto, const void *buf, int len) {
    uint8_t packet[20 + len];
    uint16_t *packet16 = (uint16_t *)packet;
    uint32_t *packet32 = (uint32_t *)packet;
    packet[0] = 0x45;    // IPv4, header length=5
    packet[1] = 0;       // TOS = original
    packet16[1] = htons(20 + len);  // Total Length
    packet16[2] = 0;     // Identification set to 0 as we don't need fragmentation
    packet[6] = 1 << 6;  // Don't fragment Flag
    packet[7] = 0;       // Fragment Offset set to zero
    packet[8] = 64;      // TTL = 64 same as Linux
    packet[9] = proto;   // Protocol
    packet32[3] = src;   // Source IP
    packet32[4] = dest;  // Destination IP
    packet16[5] = computeIPHeaderChecksum(packet);   // Header Checksum
    memcpy(packet + 20, buf, len);
    return forwardIPPacket(packet, len + 20);
}
