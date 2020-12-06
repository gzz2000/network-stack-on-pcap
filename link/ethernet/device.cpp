#include <stdio.h>
#include <pcap.h>
#include <unordered_map>
#include <vector>
#include "device.hpp"
#include "device_internal.hpp"
#include "getaddr.hpp"

std::unordered_map<std::string, int> device2id;
std::vector<Device> active_devices;

ip_t host_ip;

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
    active_devices[id].ip = getIPAddress(device);
    host_ip = active_devices[id].ip; // anyone is ok.

    fprintf(stderr, "Opened adapter '%s' with MAC address %s, system configured IP address %s.\n",
            device, mac2str(mac).c_str(),
            ip2str(active_devices[id].ip).c_str());
    
    device2id[device] = id;
    return id;
}

int findDevice(const char *device) {
    if(auto it = device2id.find(device); it == device2id.end()) return -1;
    else return it->second;
}

Device *getDeviceInfo(int id) {
    if(id < 0 || id >= (int)active_devices.size()) {
        fprintf(stderr, "[Error] Device id %d invalid.\n", id);
        return NULL;
    }
    return &active_devices[id];
}

ip_t getHostIP() {
    return host_ip;
}
