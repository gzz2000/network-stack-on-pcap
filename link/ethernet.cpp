#include <netinet/ether.h>
#include <pcap.h>
#include <string.h>
#include "ethernet.hpp"
#include "device_internal.hpp"

// One can refer to the link below.
// https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut8.html

int sendFrame(const void *buf, int len, int ethtype, const mac_t destmac, int id) {
    if(len > 1500) {
        fprintf(stderr, "[Error] sendFrame: len=%d is invalid for Ethernet II.\n", len);
        return -1;
    }
    
    Device *device = getDeviceInfo(id);
    if(device == NULL) {
        fprintf(stderr, "[Error] sendFrame: invalid device id %d.\n", id);
        return -1;
    }
    
    u_char *packet_buf = new u_char[15 + len];
    memcpy(packet_buf, destmac, 6);
    memcpy(packet_buf + 6, device->mac, 6);
    packet_buf[12] = ethtype >> 8 & 0xFF;
    packet_buf[13] = ethtype & 0xFF;
    memcpy(packet_buf + 14, buf, len);

    if(pcap_sendpacket(device->fp, packet_buf, 14 + len) != 0) {
        fprintf(stderr, "[Error] failed to send packet: %s\n", pcap_geterr(device->fp));
        delete[] packet_buf;
        return -1;
    }
    
    delete[] packet_buf;
    return 0;
}

static frameReceiveCallback callback;

int setFrameReceiveCallback(frameReceiveCallback new_callback) {
    callback = new_callback;
    return 0;
}

// see
// https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut4.html

int startCapturing(int id) {
    Device *device = getDeviceInfo(id);
    if(device == NULL) {
        fprintf(stderr, "[Error] sendFrame: invalid device id %d.\n", id);
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    while((res = pcap_next_ex(device->fp, &header, &pkt_data)) >= 0) {
        if(res == 0) continue;
        // fprintf(stderr, "Received a packet with len=%d at %ld us\n", header->len, header->ts.tv_usec);
        int ret = callback(pkt_data, header->len, id);
        if(ret < 0) {
            fprintf(stderr, "[Error] callback failed (%d), capture aborted\n", ret);
            return -1;
        }
    }

    if(res == -1) {
        fprintf(stderr, "[Error] failed to read packets: %s\n", pcap_geterr(device->fp));
        return -1;
    }
    fprintf(stderr, "startCapturing stopped for device %d.\n", id);
    return 0;
}
