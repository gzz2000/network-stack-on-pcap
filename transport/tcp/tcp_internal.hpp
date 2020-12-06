#include "inc/common.hpp"
#include "inc/messagequeue.hpp"
#include "config.hpp"
#include <unordered_map>
#include <thread>
#include <mutex>
#include <string>
#include <queue>
#include <memory>

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
}

typedef int (*tcpMessageCallback)(socket_t, socket_t, Connection &);

struct BufferSlice {
    std::shared_ptr<uint8_t[]> mem;
    std::size_t seq;
    std::size_t len;
    timer_index timer_retransmission; // only valid for send buffer
};

struct Connection {
    messagequeue<std::function<tcpMessageCallback>> q_thread; // jobs for worker thread
    persist_condition cond_socket;    // to fire a message to socket
    tcp_status status;
    timer_index timer_keepalive;
    uint32_t seq, ack;
    std::queue<BufferSlice> q_recv, q_sent;

    // seq: next byte to send
    // ack: next byte to receive
    // usrack: next byte to read from API
    // q_recv: data received but not yet read by user thread
    // q_sent: data sent but not yet acked by remote

    // TODO: initialize seq to random value upon init of Connection.
};

struct Bind {
    messagequeue<socket_t> q_socket;
    // to announce the connection of a client, put the client's socket into q_socket.
    // at the same time, the connection is put into conns[]. (TODO: implement this)
};

std::mutex pools_mutex;

// TODO: implement entry to connect to IP interface.
// it will search for both binds and conns.
std::unordered_map<std::pair<socket_t, socket_t>, Connection> conns;
std::unordered_map<socket_t, Bind> binds;

// below in worker_conn.cpp

/*
 * initialize a connection
 * seq set to random, ack set to 0, start keepalive timer
 */
Connection &init_connection(socket_t src, socket_t dest, tcp_status init_state);

void kill_connection(socket_t src, socket_t dest, Connection &conn);

void tcp_worker_conn(socket_t src, socket_t dest);

// below in process_segment.cpp
// responsible for processing remote messages

void tcp_conn_recv_segment(socket_t src, socket_t dest, Connection &conn,
                           void *iphdr /* ip packet */, void *tcpbuf,
                           int payload_len /* payload len */);

// local messages are processed within socket_wrapper.cpp,
// with definitions in socket_wrapper.hpp.

// below in utils.cpp

std::string debugSegmentSummary(void *iphdr, void *tcpbuf, int len /* payload len */);

uint16_t computeTCPChecksum(void *iphdr, void *tcpbuf, int len /* payload len */);

// below in net_interface.cpp
// responsible for connecting our tcp implementation to the network layer

/*
 * If buf set to NULL, no payload is transmitted. Else, len of payload is transmitted.
 * Note that it will NOT increment the sequence number. It is the caller's
 * duty to make sure the sequence number is properly incremented.
 * NOTIMPLEMENTED: flow control and congestion control
 */
void sendTCPSegment(socket_t src, socket_t dest, uint8_t flags,
                    uint32_t seq, uint32_t ack, void *buf, uint32_t len);
