#pragma once

/**
 * @file ip.hpp
 * @brief Library supporting sending/receiving IP packets encapsulated in an 
 * Ethernet II frame.
 */

#include <netinet/ip.h>
#include <vector>

/**
 * @brief Scan and try to open live capture on all interfaces
 * @return an array of all successfully opened devices
 */
std::vector<int> scanAllDevices();

/**
 * @brief Start listening on all devices in background.
 * will return after all threads are launched.
 */
void startIPService(const std::vector<int> &interfaces);

/**
 * @brief Send an IP packet to specified host. 
 *
 * @param src Source IP address.
 * @param dest Destination IP address.
 * @param proto Value of `protocol` field in IP header.
 * @param buf pointer to IP payload
 * @param len Length of IP payload
 * @return 0 on success, -1 on error.
 */
int sendIPPacket(const struct in_addr src, const struct in_addr dest, 
    int proto, const void *buf, int len);

/** 
 * @brief Process an IP packet upon receiving it.
 *
 * @param buf Pointer to the packet.
 * @param len Length of the packet.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);

/**
 * @brief Register a callback function to be called each time an IP packet
 * was received.
 *
 * @param callback The callback function.
 * @return 0 on success, -1 on error.
 * @see IPPacketReceiveCallback
 */
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
