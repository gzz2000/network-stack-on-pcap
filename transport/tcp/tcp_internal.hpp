#pragma once

#include "inc/common.hpp"
#include "inc/messagequeue.hpp"
#include "config.hpp"
#include <unordered_map>
#include <thread>
#include <mutex>
#include <string>
#include <queue>
#include <memory>
#include <functional>

enum tcp_status {
    STATUS_CLOSED = 0,
    STATUS_LISTEN,
    STATUS_SYN_RCVD,
    STATUS_SYN_SENT,
    STATUS_ESTAB,
    STATUS_FIN_WAIT_1,
    STATUS_FIN_WAIT_2,
    STATUS_CLOSE_WAIT,
    STATUS_LAST_ACK,
    
    /*
     * no TIME_WAIT state anymore, because
     * I think they are useless (after discussion with Kenuo Xu).
     * This also makes CLOSING and LAST_ACK identical states.
     */
    // STATUS_TIME_WAIT,
    // STATUS_TIME_WAIT_FREED,
    // STATUS_CLOSING,
    
    STATUS_TERMINATED,
    STATUS_TERMINATED_FREED
};
/*
 * TIME_WAIT -(close socket)> TIME_WAIT_FREED -(timeout)> TERMINATED_FREED
 * TIME_WAIT -(timeout)> TERMINATED -(close socket)> TERMINATED_FREED
 */

namespace std {
    template<>
    struct hash<socket_t> {
        std::size_t operator() (const socket_t &k) const {
            return std::size_t(k.ip) * 65537 + k.port;
        }
    };
    
    template<>
    struct hash<pair<socket_t, socket_t>> {
        std::size_t operator() (const pair<socket_t, socket_t> &k2) const {
            std::size_t h1 = std::size_t(k2.first.ip) * 65537 + k2.first.port;
            std::size_t h2 = std::size_t(k2.second.ip) * 65537 + k2.second.port;
            return (h1 + 1) * (~(h2 + 5));
        }
    };
}

// struct Connection;

struct BufferSlice {
    std::shared_ptr<uint8_t[]> mem;
    std::size_t seq;
    std::size_t len;
    timer_index timer_retransmission; // only valid for send buffer
};

struct Connection;

typedef void tcpMessageCallback(socket_t, socket_t, Connection &);

struct Connection {
    messagequeue<std::function<tcpMessageCallback>> q_thread; // jobs for worker thread
    persist_condition cond_socket;    // to fire a message to socket
    tcp_status status;
    timer_index timer_keepalive;
    uint32_t seq, ack, usrack;
    std::queue<BufferSlice> q_recv, q_sent;

    // seq: next byte to send
    // ack: next byte to receive
    // usrack: next byte to read from API
    // q_recv: data received but not yet read by user thread
    // q_sent: data sent but not yet acked by remote
};

struct Bind {
    messagequeue<socket_t> q_socket;
    // to announce the connection of a client, put the client's socket into q_socket.
    // at the same time, the connection is put into conns[].
};

// the actual definitions are put in worker_conn.cpp
extern std::mutex pools_mutex;

extern std::unordered_map<std::pair<socket_t, socket_t>, Connection> conns;
extern std::unordered_map<socket_t, Bind> binds;

// below in worker_conn.cpp

/*
 * initialize a connection
 * seq set to random, ack set to 0, launch worker thread, and start keepalive timer
 */
Connection &init_connection(socket_t src, socket_t dest, tcp_status init_state);

void free_connection(socket_t src, socket_t dest, Connection &conn);

void kill_connection(socket_t src, socket_t dest, Connection &conn);

void tcp_call_close(socket_t src, socket_t dest, Connection &conn);

void tcp_worker_conn(socket_t src, socket_t dest, Connection &conn);

// below in recv_segment.cpp
// responsible for processing remote messages

void tcp_conn_recv_segment(socket_t src, socket_t dest, Connection &conn,
                           const void *iphdr /* ip packet */, const void *tcpbuf,
                           int payload_len /* payload len */);

// local messages are processed within socket_wrapper.cpp,
// with definitions in socket_wrapper.hpp.

// below in net_interface.cpp
// responsible for connecting our tcp implementation to the network layer

std::string debugSegmentSummary(const void *iphdr, const void *tcpbuf, int len /* payload len */);

uint16_t computeTCPChecksum(const void *iphdr, const void *tcpbuf, int len /* payload len */);

/*
 * If buf set to NULL, no payload is transmitted. Else, len of payload is transmitted.
 * Note that it will NOT increment the sequence number. It is the caller's
 * duty to make sure the sequence number is properly incremented.
 * NOTIMPLEMENTED: flow control and congestion control
 */
void sendTCPSegment(socket_t src, socket_t dest, uint8_t flags,
                    uint32_t seq, uint32_t ack, const void *buf, uint32_t len);

// interface to give to network layer
int ipCallbackTCP(const void *buf, int len);
