#include "socket_wrapper.hpp"
#include "tcp_internal.hpp"
#include "link/ethernet/ethernet.hpp"
#include "ip/ip.hpp"
#include <mutex>
#include <unordered_map>

#define VIRTUAL_SOCKET_FD_ST 100000

int nxt_vsock_fd = VIRTUAL_SOCKET_FD_ST;

enum socket_type {
    SOCKET_TYPE_IDLE = 0,
    SOCKET_TYPE_BIND,
    SOCKET_TYPE_CONN,
};

struct SocketInfo {
    socket_type type;
    socket_t src, dest;
};

std::mutex sockets_mutex;
std::unordered_map<int, SocketInfo> sockets;

int __wrap_socket(int domain, int type, int protocol) {
    std::scoped_lock lock(sockets_mutex);
    int id = nxt_vsock_fd++;
    sockets[id] = {SOCKET_TYPE_IDLE, {0, 0}, {0, 0}};
    return id;
}

static int system_to_socket_t(const struct sockaddr *address,
                              socklen_t address_len,
                              socket_t &ret) {
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    if(addr->sin_family != AF_INET) {
        fprintf(stderr, "bind() only support IPv4\n");
        errno = EINVAL;
        return -1;
    }
    ret.ip = addr->sin_addr.s_addr;
    ret.port = addr->sin_port;
}

static int socket_t_to_system(socket_t s,
                              struct sockaddr *address, socklen_t *address_len) {
    if(*address_len < sizeof(struct sockaddr_in)) {
        // not enough space for address store
        errno = EINVAL;
        return -1;
    }
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = s.ip;
    addr->sin_port = s.port;
    *address_len = sizeof(struct sockaddr_in);
    return 0;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    // https://man7.org/linux/man-pages/man7/ip.7.html
    std::scoped_lock lock(sockets_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }
    
    SocketInfo &si = it->second;
    return system_to_socket_t(address, address_len, si.src);
}

static int finalize_socket_src(SocketInfo &si) {
    if(!si.src.ip) si.src.ip = getHostIP();
    if(!si.src.port) {
        // choose an ephemeral address from 32769 to 60999
        si.src.port = 32769u;
        while(binds.count(si.src)) {
            ++si.src.port;
            if(si.src.port == 61000u) {
                // no ephemeral port available
                errno = EADDRINUSE;
                return -1;
            }
        }
    }
    if(binds.count(si.src)) {
        // specified port unavailable
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

int __wrap_listen(int socket, int backlog) {
    // NOTIMPLEMENTED: backlog is ignored.
    std::scoped_lock lock(sockets_mutex, pools_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }

    SocketInfo &si = it->second;
    if(-1 == finalize_socket_src(si)) return -1;
    binds[si.src] = {};
    si.type = SOCKET_TYPE_BIND;
    return 0;
}

int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_BIND) {
        fprintf(stderr, "socket not listening\n");
        errno = EINVAL;
        return -1;
    }
    socket_t src = it->second.src;
    Bind &bind = binds[src];

    lock_sockets.unlock();
    lock_pools.unlock();

    socket_t client = bind.q_socket.pop();
    if(-1 == socket_t_to_system(client, address, address_len)) {
        bind.q_socket.push(client);  // re-push it back..
        return -1;
    }

    std::lock(lock_sockets, lock_pools);
    
    // create a new socket descriptor along with the connection.
    int id = nxt_vsock_fd++;
    sockets[id] = {SOCKET_TYPE_CONN, src, client};
    return id;
}

int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    std::unique_lock<std::mutex> lock(sockets_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }
    SocketInfo &si = it->second;

    lock.unlock();
    socket_t s_dest;
    if(-1 == system_to_socket_t(address, address_len, s_dest)) return -1;
    if(-1 == finalize_socket_src(si)) return -1;

    Connection &conn = init_connection(si.src, s_dest, STATUS_SYN_SENT);
    sendTCPSegment(si.src, s_dest, TH_SYN, conn.seq - 1, conn.ack, NULL, 0);
    while(true) {
        if(conn.status == STATUS_ESTAB ||
           conn.status == STATUS_CLOSE_WAIT) break;
        else if(conn.status == STATUS_TERMINATED) {
            conn.status = STATUS_TERMINATED_FREED;
            // note here we don't distinguish between ETIMEOUT and ECONNREFUSED
            errno = ECONNREFUSED;
            return -1;
        }
        conn.cond_socket.get();   // block to watch state change
    }

    lock.lock();
    int id = nxt_vsock_fd++;
    sockets[id] = {SOCKET_TYPE_CONN, si.src, s_dest};
    return id;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbyte) {
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(fd);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_CONN){
        fprintf(stderr, "socket is not an established connection\n");
        errno = EINVAL;
        return -1;
    }
    // socket_t src = it->second.src, dest = it->second.dest;
    Connection &conn = conns[std::make_pair(src, dest)];

    lock_sockets.unlock();
    lock_pools.unlock();

    while(true) {
        if(!conn.q_recv.empty()) {
            size_t i = 0;
            do {
                BufferSlice &bs = conn.q_recv.front();
                size_t read_len = std::min(bs.len - (conn.usrack - bs.seq), nbyte - i);
                memcpy(buf + i, mem.get() + conn.usrack - bs.seq, read_len);
                conn.usrack += read_len;
                i += read_len;
                if(conn.usrack >= bs.seq + bs.len) conn.q_recv.pop();
            }
            while(!conn.q_recv.empty() && i != nbyte);
            return i;
        }
        else if(conn.status == STATUS_CLOSE_WAIT || conn.status == STATUS_LAST_ACK ||
                conn.status == STATUS_TERMINATED) {
            return 0;   // EOF
        }
        conn.cond_socket.get();   // block to watch data arrival or state change
    }
}

// this will add a retransmission timer
static void do_transmit(BufferSlice &bs,
                        socket_t src, socket_t dest, Connection &conn) {
    sendTCPSegment(src, dest, TH_ACK, bs.seq, conn.ack, bs.mem.get(), bs.len);
    bs.timer_retransmission = \
        conn.q_thread.setTimeout([&bs] (socket_t src, socket_t dest, Connection &conn) {
                do_transmit(bs, src, dest, conn);
            }, TIMEOUT_RETRANSMISSION);
}

ssize_t __wrap_write(int fd, const void *buf, size_t nbyte) {
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(fd);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_CONN){
        fprintf(stderr, "socket is not an established connection\n");
        errno = EINVAL;
        return -1;
    }
    socket_t src = it->second.src, dest = it->second.dest;
    Connection &conn = conns[std::make_pair(src, dest)];

    lock_sockets.unlock();
    lock_pools.unlock();

    if(conn.status == STATUS_FIN_WAIT_1 || conn.status == STATUS_FIN_WAIT_2 ||
       conn.status == STATUS_TERMINATED) {
        erno = EPIPE;  // NOTIMPLEMENTED: no sigpipe sent.
        return 0;     // client side already closed. \
                      in fact, only TERMINATED is expected in current implementation.
    }

    // NOTIMPLEMENTED: no any form of window. all data are sent at once, \
    congesting the network at the furthest possible.

    size_t i = 0;
    while(nbyte) {
        size_t len = std::min(nbyte - i, (size_t)TCP_MTU);
        conn.q_sent.emplace({new uint8_t[len], conn.seq, len, {}});
        BufferSlice &bs = conn.q_sent.back();
        memcpy(bs.mem.get(), buf + i, len);
        do_transmit(bs, src, dest, conn);
        i += len;
    }
    return nbyte;
}

int __wrap_close(int socket) {
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(fd);
    if(it == sockets.end()) {
        fprintf(stderr, "socket fd invalid\n");
        errno = EBADF;
        return -1;
    }

    if(it->second.type == SOCKET_TYPE_IDLE) {
        // do nothing just remove it.
        sockets.erase(it);
        return 0;
    }
    else if(it->second.type == SOCKET_TYPE_BIND) {
        // manually remove the bind item
        binds.erase(it->second.src);
        sockets.erase(it);
        return 0;
    }

    // else: it->second.type != SOCKET_TYPE_CONN
    socket_t src = it->second.src, dest = it->second.dest;
    Connection &conn = conns[std::make_pair(src, dest)];

    lock_sockets.unlock();
    lock_pools.unlock();

    while(conn.status != STATUS_TERMINATED) {
        switch(conn.status) {
        case STATUS_SYN_SENT:
            conn.status = STATUS_TERMINATED;
            break;
        
        case STATUS_SYN_RCVD:
        case STATUS_ESTAB:
            sendTCPSegment(src, dest, TH_FIN, conn.seq, conn.ack, NULL, 0);
            conn.status = STATUS_FIN_WAIT_1;
            break;

        case STATUS_CLOSE_WAIT:
            sendTCPSegment(src, dest, TH_FIN, conn.seq, conn.ack, NULL, 0);
            conn.status = STATUS_LAST_ACK;
            break;
        }
        conn.cond_socket.get();    // block until another change.
    }
    conn.status = STATUS_TERMINATED_FREED;

    lock_sockets.lock();
    sockets.erase(it);
    return 0;
}

