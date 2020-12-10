#pragma once

// NOTIMPLEMENTED: keepalive probe segment
// NOTIMPLEMENTED: time wait. I think this is not essential and only introducing problem

// #define TIMEOUT_TIMEWAIT 60000  // 1 min

// after this amount of idle the connection is terminated abruptly.
#define TIMEOUT_KEEPALIVE 120000  // 2 min.

#define TIMEOUT_RETRANSMISSION 5000  // 5s

#define TCP_DATA_MTU 1300  // 1200 bytes

#define TCP_WINDOW_SIZE TCP_DATA_MTU

// originally, window size is set to 16384(16kB)..
// however, when testing with real machines, they sent back fragmented IP packets
// which my IP layer is not able to handle.
// as a result I have to lower the window size just to make it work.
