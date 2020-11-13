#include <cstdio>
#include <string>
#include <cstring>
#include <link/device.hpp>
#include <link/ethernet.hpp>
#include <netinet/ether.h>

int receiveCallback(const void *buf, int len, int id) {
    printf("id = %d, len = %d\n", id, len);
    for(int i = 0; i < len; ++i) printf("%02x ", (unsigned char)((const char *)buf)[i]);
    putchar('\n');
    return 0;
}

int main(int argc, char **argv) {
    if(argc != 3 || (argv[2] != std::string("send") && argv[2] != std::string("recv"))) {
        fprintf(stderr, "Usage: %s [vethX-X] [send/recv]\n", argv[0]);
        return -1;
    }
    int id = addDevice(argv[1]);
    if(id < 0) return -1;
    if(argv[2] == std::string("send")) {
        printf("Enter receiver MAC address and a word as content, one line each.\n");
        while(true) {
            char buf[SNAPLEN], macaddr[20];
            scanf("%s%s", macaddr, buf);
            struct ether_addr *ea = ether_aton(macaddr);
            if(ea == NULL) {
                printf("[Error] invalid MAC: %s\n", macaddr);
                continue;
            }
            int ret = sendFrame(buf, strlen(buf), 0x2333 /* test */, ea->ether_addr_octet, id);
            printf("sendFrame returns %d\n", ret);
        }
    }
    else {
        setFrameReceiveCallback(receiveCallback);
        startCapturing(id);
    }
    return 0;
}
