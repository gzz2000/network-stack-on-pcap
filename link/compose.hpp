#pragma once

/**
 * @file compose.hpp
 * @brief Multi-thread listening on a set of interfaces
 */

#include "ethernet.hpp"
#include <vector>

/**
 * @brief start capturing on a multiple of device IDs
 * @param interfaces the list of device IDs to listen on
 * returns on error, in which case not all threads are released.
 * 
 */
void startComposedCapturing(std::vector<int> interfaces);
