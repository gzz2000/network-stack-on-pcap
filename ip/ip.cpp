#include <pcap.h>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include "inc/common.hpp"
#include "link/ethernet/getaddr.hpp"
#include "link/ethernet/device.hpp"
#include "link/ethernet/device_internal.hpp"
#include "link/ethernet/ethernet.hpp"
#include "link/ethernet/compose.hpp"
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

// forwardIPPacket is called by frameCallback, and also by
// IP layer users through sendIPPacket.
// forwardIPPacket assumes a valid IPv4 header. It should be checked before calling this.
// it either forward the IP packet according to routing table,
// or calling ip_callback if its destination is this host.
// IMPORTANT NOTICE:
// If called by IP layer users, you might like to make your ip_callback
// not only thread-safe, but REENTRANT.
// OTHERWISE, you should NEVER call sendIPPacket within a ip_callback.
static int forwardIPPacket(const void *buf, int len) {
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
            if(*((const uint8_t *)buf + 8) == 0) {
                fprintf(stderr, "Dropped a IP packet with TTL=0 dest %s\n",
                        ip2str(dest).c_str());
                // NOT IMPLEMENTED: sending back a ICMP message 11
                return 0;
            }
            else {
                fprintf(stderr, "Forwarding a IP packet dest %s to device %d\n",
                        ip2str(dest).c_str(), rte->next_device_id);
                sendFrame(buf, len, ETHER_TYPE_IP, rte->next_hop_mac, rte->next_device_id);
                return 0;
            }
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
        if(len - 14 < 20) {
            fprintf(stderr, "[IP Error] received IP frame with bad packet len=%d\n",
                    len - 14);
            return 0;
        }
        uint8_t *ip_buf = new uint8_t[len - 14];
        memcpy(ip_buf, (const uint8_t *)buf + 14, len - 14);
        uint8_t signature = *(const uint8_t *)ip_buf;
        uint8_t version = signature >> 4;
        if(version != 4) {
            fprintf(stderr, "[IP Error] cannot work with IPv%u\n", (uint32_t)version);
            delete[] ip_buf;
            return 0;
        }
        
        uint16_t checksum = *((const uint16_t *)ip_buf + 5);
        if(computeIPHeaderChecksum(ip_buf) != checksum) {
            fprintf(stderr, "[IP Error] received a IP packet with bad header checksum.\n");
            delete[] ip_buf;
            return 0;
        }
        
        // decrement TTL and recompute checksum
        --*((uint8_t *)ip_buf + 8);
        *((uint16_t *)ip_buf + 5) = computeIPHeaderChecksum(ip_buf);
        
        // forward the packet.
        // If the packet is to be routed but TTL=0, then discarded within this call.
        int ret = forwardIPPacket(ip_buf, len - 14);
        delete[] ip_buf;
        return ret;
    }
    else {
        fprintf(stderr, "Unrecognized ethtype: 0x%04x\n", ethtype);
        return -1;
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
    ip_header_t *iphdr = (ip_header_t *)packet;
    iphdr->ver = 4;
    iphdr->ihl = 5;
    iphdr->ds = 0;
    iphdr->ecn = 0;
    iphdr->total_length = htons(20 + len);
    iphdr->flags_fo = 0;
    iphdr->ttl = 64;
    iphdr->protocol = proto;
    iphdr->src = src;
    iphdr->dest = dest;
    iphdr->checksum = computeIPHeaderChecksum(packet);
    memcpy(packet + 20, buf, len);
    return forwardIPPacket(packet, len + 20);
}
