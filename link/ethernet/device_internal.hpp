#pragma once

#include <pcap.h>
#include "common.hpp"
#include "inc/common.hpp"

struct Device {
    pcap_t *fp;
    mac_t mac;
    ip_t ip;
    frameReceiveCallback special_callback;
};

// internal function for obtaining device info
Device *getDeviceInfo(int id);
