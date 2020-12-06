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

struct tcp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;  // 4 bits, then comes 3 reserved and 1 NS flag bit
    uint8_t  flags;
    uint16_t window_size;  // i shall set it to a large one?
    uint16_t checksum;
    uint16_t urgent_p;
};

#ifndef TH_FIN
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#endif
