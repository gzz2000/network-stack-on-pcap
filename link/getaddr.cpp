#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include "inc/common.hpp"

void getMACAddress(const char *device, mac_t store) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, 0);
    // can also be AF_INET which would let this run in non-privileged mode.
    // However, I personally hate AF_INET here just because it introduces (although immediately releases)
    //   unnecessary OS-implemented high-level stack which should be implemented by ourselves.
    // one can also use getifaddrs-like interface to get MAC address.. but I don't use that.
    // other methods include reading sysfs and using ether_ntoa?
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(store, ifr.ifr_hwaddr.sa_data, 6);
}

ip_t getIPAddress(const char *device) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

std::string ip2str(ip_t ip) {
    return inet_ntoa((struct in_addr){ip});
}

std::string mac2str(const mac_t mac) {
    char ret[20];
    sprintf(ret, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ret;
}
