#include <pcap.h>
#include <cstring>
#include <thread>
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
        onRoutingPacket((char *)buf + 14, len - 14, mac, id);
        return 0;
    }
    else if(ethtype == ETHER_TYPE_IPv4) {
        // todo: only receive IPs correspond to our hosts, and forward other IPs.
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
