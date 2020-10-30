#pragma once

#include <pcap.h>

struct Device {
    pcap_t *fp;
    u_char mac[6];
};

// internal function for obtaining device info
Device *getDeviceInfo(int id);
