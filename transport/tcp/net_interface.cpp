#include "tcp_internal.hpp"

void sendTCPSegment(socket_t src, socket_t dest, uint8_t flags,
                    uint32_t seq, uint32_t ack, void *buf, uint32_t len);
// TODO: implement this. simple packet assembly
