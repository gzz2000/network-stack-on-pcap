#pragma once

#include <cstdint>

typedef unsigned int uint;
typedef uint8_t mac_t[8];
typedef uint32_t ip_t;     // actually we may like to use struct in_addr.
// but for simplicity...

struct socket_t {
    ip_t ip;
    uint16_t port;
};

inline bool operator == (socket_t a, socket_t b) {
    return a.ip == b.ip && a.port == b.port;
}

struct ip_header_t {
    uint ver: 4;
    uint ihl: 4;
    uint ds: 6;
    uint ecn: 2;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    ip_t   src;
    ip_t   dest;
};

