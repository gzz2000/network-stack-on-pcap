#pragma once

#include <pcap.h>
#include "inc/common.hpp"

struct Device {
    pcap_t *fp;
    mac_t mac;
};

// internal function for obtaining device info
Device *getDeviceInfo(int id);
