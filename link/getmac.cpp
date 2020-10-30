#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

void getMACAddress(const char *device, unsigned char *store) {
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
