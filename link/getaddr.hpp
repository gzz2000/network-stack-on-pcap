#pragma once

#include "inc/common.hpp"
#include <string>

void getMACAddress(const char *device, mac_t store);
ip_t getIPAddress(const char *device);

std::string ip2str(ip_t ip);
std::string mac2str(const mac_t mac);
