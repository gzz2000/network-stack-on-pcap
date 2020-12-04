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
 * will return after all threads are launched
 * 
 */
void startComposedCapturing(std::vector<int> interfaces);
