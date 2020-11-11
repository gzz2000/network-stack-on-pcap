#include <mutex>
#include <list>
#include <thread>
#include <chrono>
#include "routing.hpp"
#include "link/device_internal.hpp"
#include "link/getaddr.hpp"
#include "link/ethernet.hpp"

using namespace std::chrono_literals;

std::mutex routing_table_mutex;
std::list<RoutingTableEntry> routing_table;

static int initRoutingTable(const std::vector<int> &interfaces) {
    std::scoped_lock lock(routing_table_mutex);
    routing_table.clear();
    for(int id: interfaces) {
        Device *device = getDeviceInfo(id);
        if(device == NULL) {
            fprintf(stderr, "[IP Error] Device id %d invalid.\n", id);
            return -1;
        }
        setRoutingTable({device->ip, (ip_t)~0 /* single IP */,
                    -1 /* this device.*/,
                    {device->mac[0], device->mac[1], device->mac[2],
                            device->mac[3], device->mac[4], device->mac[5]},
                    0});
    }
    return 0;
}

static int announceRoutingTable(const std::vector<int> &interfaces) {
    std::scoped_lock lock(routing_table_mutex);
    int len = sizeof(int) + routing_table.size() * sizeof(RoutingInformation);
    void *buf = new char[len];
    char *buf_p = (char *)buf;
    *(int *)buf_p = (int)routing_table.size();
    buf_p += sizeof(int);
    for(const RoutingTableEntry &rte: routing_table) {
        *(RoutingInformation *)buf_p = {rte.dest, rte.mask, rte.hop + 1};
        buf_p += sizeof(RoutingInformation);
    }
    for(int id: interfaces) {
        Device *device = getDeviceInfo(id);
        if(device == NULL) {
            fprintf(stderr, "[IP Error] on getDeviceInfo. exiting announceRoutingTable\n");
            return -1;
        }
        if(sendFrame(buf, len, ETHER_TYPE_ROUTING, device->mac, id) == -1) {
            fprintf(stderr, "[IP Error] Failed to send routing table to device %d\n", id);
            return -1;
        }
    }
    return 0;
}

void announceServiceWorker(const std::vector<int> interfaces) {
    if(initRoutingTable(interfaces) == -1) {
        fprintf(stderr, "[IP Error] initRoutingTable failed\n");
        return;
    }
    while(true) {
        if(announceRoutingTable(interfaces) == -1) {
            fprintf(stderr, "[IP Error] announceRoutingTable failed\n");
            return;
        }
        std::this_thread::sleep_for(100ms);
    }
}

void clearRoutingTableToID(int id) {
    for(auto it = routing_table.begin(); it != routing_table.end(); ) {
        if(it->next_device_id == id) routing_table.erase(it++);
        else ++it;
    }
}

void setRoutingTable(RoutingTableEntry rte_new) {
    if(rte_new.hop > MAX_HOP) return;
    for(RoutingTableEntry &rte: routing_table) {
        if(rte.dest == rte_new.dest && rte.mask == rte_new.mask) {
            if(rte.hop > rte_new.hop) rte = rte_new;
            return;
        }
    }
    routing_table.push_front(rte_new);
}

void onRoutingPacket(const void *buf, int len, mac_t src_mac, int id) {
    if(len < sizeof(int) ||
       len < (sizeof(int) + sizeof(RoutingInformation) * *(const int *)buf)) {
        fprintf(stderr,
                "[IP Error]"
                " too small length of routing packet: %d from device %d. Dropping it.\n",
                len, id);
        return;
    }

    Device *device = getDeviceInfo(id);
    if(device == NULL) {
        //error.
        return;
    }
    
    std::scoped_lock lock(routing_table_mutex);
    clearRoutingTableToID(id);
    int sz = *(int *)buf;
    const RoutingInformation *ri_p =
        (const RoutingInformation *)((char *)buf + sizeof(int));
    for(int i = 0; i < sz; ++i) {
        setRoutingTable({ri_p[i].dest, ri_p[i].mask, id,
                {src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]},
                    ri_p[i].hop + 1});
    }

    // print
    debugPrintRoutingTable();
}

std::optional<RoutingTableEntry> queryRoutingTable(ip_t ip) {
    std::scoped_lock lock(routing_table_mutex);
    
    std::optional<RoutingTableEntry> match;
    for(const RoutingTableEntry &rte: routing_table) {
        if(rte.dest == (ip & rte.mask)) {
            if(!match || match->mask < rte.mask) { // longest prefix matching
                match = rte;
            }
        }
    }
    return match;
}

void debugPrintRoutingTable() {
    typedef unsigned long long ull;
    static ull last_hash;
    ull this_hash = 0;
    for(const RoutingTableEntry &rte: routing_table) {
        ull mac_hash = 0;
        for(int i = 0; i < 6; ++i) mac_hash = mac_hash << 8 | rte.next_hop_mac[i];
        this_hash ^= ((((((ull)rte.dest << 32ll | rte.mask) + 7) * 10007ll
                        + rte.next_device_id) * 281474976710677ll
                       + mac_hash) * 10039ll
                      + rte.hop) * 10079ll;
    }
    if(this_hash == last_hash) return;
    last_hash = this_hash;

    fprintf(stderr, "======================================\nRouting Table Changed:\n");
    for(const RoutingTableEntry &rte: routing_table) {
        fprintf(stderr, "IP %s, MASK %s -> Device %d, MAC %s, hop=%d\n",
                ip2str(rte.dest).c_str(), ip2str(rte.mask).c_str(),
                rte.next_device_id,
                mac2str(rte.next_hop_mac).c_str(),
                rte.hop);
    }
    fprintf(stderr, "======================================\n");
}
