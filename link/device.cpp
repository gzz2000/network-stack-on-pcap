#include <stdio.h>
#include <pcap.h>
#include <unordered_map>
#include <vector>
#include "device.hpp"
#include "device_internal.hpp"
#include "getmac.hpp"

std::unordered_map<std::string, int> device2id;
std::vector<Device> active_devices;

int addDevice(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = 0;
    
    pcap_t *fp = pcap_open_live(device, SNAPLEN, 1, READ_TIMEOUT, errbuf);
    if(errbuf[0]) {
        fprintf(stderr, "[Warning] pcap_open_live '%s': %s\n", device, errbuf);
    }
    if(fp == NULL) {
        fprintf(stderr, "[Error] Unable to open adapter '%s'.\n", device);
        return -1;
    }
    
    active_devices.emplace_back();
    int id = (int)active_devices.size() - 1;
    active_devices[id].fp = fp;
    u_char *mac = active_devices[id].mac;
    getMACAddress(device, mac);

    fprintf(stderr, "Opened adapter '%s' with MAC address %.2x:%.2x:%.2x:%.2x:%.2x:%.2x.\n", device, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    device2id[device] = id;
    return id;
}

int findDevice(const char *device) {
    if(auto it = device2id.find(device); it == device2id.end()) return -1;
    else return it->second;
}

Device *getDeviceInfo(int id) {
    if(id < 0 || id >= (int)active_devices.size()) return NULL;
    return &active_devices[id];
}
