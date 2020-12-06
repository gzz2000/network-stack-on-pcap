#include "tcp_internal.hpp"
#include <cstdlib>
#include <thread>

Connection &init_connection(socket_t src, socket_t dest, tcp_status init_state) {
    Connection &conn = conns[std::make_pair(src, dest)];
    conn.status = init_state;
    conn.seq = rand();
    conn.ack = 0;
    conn.q_thread.setTimeout(kill_connection, TIMEOUT_KEEPALIVE);
    std::thread thread_worker(tcp_worker_conn, src, dest, conn);
    thread_worker.detach();
    return conn;
}

void kill_connection(socket_t src, socket_t dest, Connection &conn) {
    /*
     * This is called when keepalive timer alarms or an RST is received.
     */
    sendTCPSegment(src, dest, TH_RST, conn.seq, conn.ack, NULL, 0);
    while(!conn.q_sent.empty()) {
        conn.q_thread.clearTimeout(conn.q_sent.front().timer_transmission);
        conn.q_sent.pop();
    }
    conn.status = STATUS_TERMINATED;
    conn.cond_socket.set();    // send EOF
}

void tcp_worker_conn(socket_t src, socket_t dest, Connection &conn) {
    /*
     * Main event loop.
     */
    while(conn.status != STATUS_TERMINATED_FREED) {
        conn.q_thread.pop()(src, dest, conn);
    }

    std::scoped_lock lock(pools_mutex);
    conns.erase(std::make_pair(src, dest));
}
