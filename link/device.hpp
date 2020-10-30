#pragma once

/** 
 * @file device.hpp
 * @brief Library supporting network device management.
 */

#include "common.hpp"

/**
 * Add a device to the library for sending/receiving packets. 
 *
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int addDevice(const char* device);

/**
 * Find a device added by `addDevice`.
 *
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device 
 * was found.
 */
int findDevice(const char* device);
