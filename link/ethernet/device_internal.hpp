#pragma once

#include <pcap.h>
#include "inc/common.hpp"

struct Device {
    pcap_t *fp;
    mac_t mac;
    ip_t ip;
};

// internal function for obtaining device info
Device *getDeviceInfo(int id);
