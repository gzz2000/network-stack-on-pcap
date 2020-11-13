#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
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
        // input like: <src IP> <dest IP> content
        // eg: 10.100.1.1 10.100.3.1 helloworld
        char srcip[20], destip[20], content[100];
        scanf("%s%s%s", srcip, destip, content);
        struct in_addr addr_src, addr_dest;
        if(inet_aton(srcip, &addr_src) == 0) {
            fprintf(stderr, "[App Error] IP parse failed: %s\n", srcip);
            continue;
        }
        if(inet_aton(destip, &addr_dest) == 0) {
            fprintf(stderr, "[App Error] IP parse failed: %s\n", destip);
            continue;
        }
        int ret = sendIPPacket(addr_src.s_addr, addr_dest.s_addr,
                               253 /* IANA reserved test protocol */,
                               content, strlen(content));
        fprintf(stderr, "sendIPPacket returns %d\n", ret);
    }
    return 0;
}
