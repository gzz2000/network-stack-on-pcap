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
    // actually ver first, and then ihl. however, when bit fields are used, we have to reverse their order on little endian.
    // https://stackoverflow.com/a/58127442/11815215
    // so generally we discourage the use of bit fields..
    
    uint8_t ver_ihl;
    uint8_t ds_ecn;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    ip_t   src;
    ip_t   dest;
};

