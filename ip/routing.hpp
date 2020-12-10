#pragma once

/**
 * @file routing.hpp
 * @brief Manages, exchanges routing information on top of ethernet, and 
 * provides routing table to IP layers
 */

#include <optional>
#include <mutex>
#include <vector>
#include "inc/common.hpp"

const int MAX_HOP = 1000;  // when hop count > this, entries are deleted

/**
 * @brief The loop of announce service.
 * This service periodically sends routing info to neighbors. (announcement)
 * This function is expected to be called in a separate thread.
 * @param interfaces the interfaces to send packets to.
 */
void announceServiceWorker(const std::vector<int> interfaces, bool is_gateway);

struct RoutingTableEntry {
    ip_t dest, mask;
    int next_device_id;
    mac_t next_hop_mac;
    int hop;
};

// this piece of information is sent in announcement packets.
struct RoutingInformation {
    ip_t dest, mask;
    int hop;
};

/**
 * @brief Called on receival of a routing table packet
 * This is a frameReceiveCallback-like interface. However, it is not directly
 * registered, but called by another callback instead.
 *
 * Another important difference is that the buf and len refer to the content
 * of the frame instead of the full frame. Keep notice on that.
 * As a result, you also need to parse and pass the source mac address when calling.
 * 
 */
void onRoutingPacket(const void *buf, int len, mac_t src_mac, int id);

/**
 * @brief Query the routing table.
 * @param ip the IP address to query.
 * @return nullptr if not found, and RoutingTableEntry if found.
 */
std::optional<RoutingTableEntry> queryRoutingTable(ip_t ip);

// ====================== internal
// The function interfaces below are NOT locked, and you should ensure they are not
// called simutaneously by multiple threads, or use this global lock.
extern std::mutex routing_table_mutex;

/**
 * @brief Clear routing table for a specific next device.
 * Useful for updating outdated information.
 * @param id The id to search for and remove in routing table.
 */
void clearRoutingTableToID(int id);

/**
 * @brief Add an item to routing table.
 * Can be used to manully add an item to routing table. Useful when talking with real 
 * Linux machines.
 * 
 * @param rte: the routing table entry to be inserted.
 */
void setRoutingTable(RoutingTableEntry rte);

/**
 * @brief Pretty print current routing table, for debugging purpose.
 * Will not print if the routing table is not changed since last call.
 */
void debugPrintRoutingTable();
