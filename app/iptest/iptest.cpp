#include <cstdio>
#include "ip/ip.hpp"

int ipPacketCallback(const void *buf, int len) {
    printf("IP Packet: len = %d\n", len);
    for(int i = 0; i < len; ++i) printf("%02x ", (unsigned char)((const char *)buf)[i]);
    putchar('\n');
    return 0;
}

int main() {
    setIPPacketReceiveCallback(ipPacketCallback);
    startIPService(scanAllDevices("veth"));
    //Enter REPL
    while(true) {
        getchar();   // do nothing this time
    }
    return 0;
}
