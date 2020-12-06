#pragma once

/** 
 * @file packetio.h => ethernet.hpp
 * @brief Library supporting sending/receiving Ethernet II frames.
 */

#include "common.hpp"
#include "device.hpp"
#include "inc/common.hpp"

/** 
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device(returned by `addDevice`) to send on.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int sendFrame(const void* buf, int len, 
    int ethtype, const mac_t destmac, int id);

/** 
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame.
 * @param len Length of the frame.
 * @param id ID of the device (returned by `addDevice`) receiving current 
 * frame.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
typedef int (*frameReceiveCallback)(const void*, int, int);

/**
 * @brief Register a callback function to be called each time an Ethernet II 
 * frame was received.
 *
 * @param callback the callback function.
 * @return 0 on success, -1 on error.
 * @see frameReceiveCallback
 */
int setFrameReceiveCallback(frameReceiveCallback callback);

/**
 * @brief Start capturing on the specific device ID.
 * @param id the device ID to run capture on.
 * @return -1 on error. Doesn't return when success.
 *
 */
int startCapturing(int id);

/**
 * @brief return any IP address of this host
 * useful for wildcard binding in later socket implementation.
 */
ip_t getHostIP();
