#include <cstdio>
#include "inc/common.hpp"
#include "link/ethernet/device.hpp"
#include "link/ethernet/ethernet.hpp"
#include "ip/ip.hpp"

/*
 * TODO:
 * 1. broadcast 0.0.0.0 to inner network
 * 2. set up a translation table for TCP
 *
 */

// static int realid;

// int realFrameReceiveCallback(const void *buf, int len, int id) {
//     // TODO
// }

int ipPacketCallback(const void *buf, int len) {
    // // ???
    
    // printf("IP Packet: len = %d\n", len);
    // for(int i = 0; i < len; ++i) printf("%02x ", (unsigned char)((const char *)buf)[i]);
    // putchar('\n');
    // return 0;
    return 0;
}

int main(int argc, char **argv) {
    // if(argc != 2) {
    //     fprintf(stderr, "Usage: %s <dev>\ndev: name of the real ethernet device to send Internet packet to.\n",
    //             argv[0]);
    //     return -1;
    // }
    // realid = addDeviceWithCallback(argv[1], realFrameReceiveCallback);
    // if(realid < 0) {
    //     fprintf(stderr, "[NAT Error] Cannot open device %s for forwarding.\n",
    //             argv[1]);
    //     return -1;
    // }
    // std::thread t_real(startCapturing, realid);
    // t_real.detach();
    
    setIPPacketReceiveCallback(ipPacketCallback);
    startIPService(scanAllDevices("veth"), /* is_gateway = */ true);

    while(true) getchar();   // infinite loop
    return 0;
}
