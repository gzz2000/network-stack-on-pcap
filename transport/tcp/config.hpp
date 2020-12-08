#pragma once

// NOTIMPLEMENTED: keepalive probe segment
// NOTIMPLEMENTED: time wait. I think this is not essential and only introducing problem

// #define TIMEOUT_TIMEWAIT 60000  // 1 min

// after this amount of idle the connection is terminated abruptly.
#define TIMEOUT_KEEPALIVE 120000  // 2 min.

#define TIMEOUT_RETRANSMISSION 5000  // 5s

#define TCP_DATA_MTU 1200  // 1200 bytes

