#include "tcp_internal.hpp"
#include <thread>
#include <chrono>

std::mutex pools_mutex;

std::unordered_map<std::pair<socket_t, socket_t>, Connection> conns;
std::unordered_map<socket_t, Bind> binds;

inline static uint32_t gen_seq() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(high_resolution_clock::now().time_since_epoch()).count();
}

Connection &init_connection(socket_t src, socket_t dest, int q_socket_fd, tcp_status init_state) {
    Connection &conn = conns[std::make_pair(src, dest)];
    conn.status = init_state;
    conn.seq = gen_seq();
    conn.ack = 0;
    conn.q_socket_fd = q_socket_fd;
    conn.timer_keepalive = conn.q_thread.setTimeout(kill_connection, TIMEOUT_KEEPALIVE);
    conn.thread_worker = std::thread(tcp_worker_conn, src, dest, std::ref(conn));
    return conn;
}

void free_connection(socket_t src, socket_t dest, Connection &conn) {
    // fprintf(stderr, "Tagging the connection as freed.\n");
    conn.status = STATUS_TERMINATED_FREED;
}

void kill_connection(socket_t src, socket_t dest, Connection &conn) {
    /*
     * This is called when keepalive timer alarms or an RST is received.
     */
    sendTCPSegment(src, dest, TH_RST, conn.seq, conn.ack, NULL, 0);
    while(!conn.q_sent.empty()) {
        conn.q_thread.clearTimeout(conn.q_sent.front().timer_retransmission);
        conn.q_sent.pop();
    }
    conn.status = STATUS_TERMINATED;
    conn.cond_socket.set();    // send EOF
}

void tcp_call_close(socket_t src, socket_t dest, Connection &conn) {
    switch(conn.status) {
    case STATUS_SYN_SENT:
        conn.status = STATUS_TERMINATED;
        conn.cond_socket.set();
        break;
        
    case STATUS_SYN_RCVD:
    case STATUS_ESTAB:
        sendTCPSegment(src, dest, TH_FIN | TH_ACK, conn.seq, conn.ack, NULL, 0);
        ++conn.seq;
        conn.status = STATUS_FIN_WAIT_1;
        break;

    case STATUS_CLOSE_WAIT:
        sendTCPSegment(src, dest, TH_FIN | TH_ACK, conn.seq, conn.ack, NULL, 0);
        ++conn.seq;
        conn.status = STATUS_LAST_ACK;
        break;

    default:
        fprintf(stderr, "[TCP Error] Unexpected state when closing.\n");
        conn.status = STATUS_TERMINATED;
        conn.cond_socket.set();
    }
}

void tcp_worker_conn(socket_t src, socket_t dest, Connection &conn) {
    /*
     * Main event loop.
     */
    while(conn.status != STATUS_TERMINATED_FREED) {
        auto f = conn.q_thread.pop();
        std::scoped_lock lock(conn.conn_mutex);
        f(src, dest, conn);
    }
}
