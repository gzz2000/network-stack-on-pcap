#include "socket_wrapper.hpp"
#include "tcp_internal.hpp"
#include "service.hpp"
#include "link/ethernet/device.hpp"
#include "ip/ip.hpp"
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <arpa/inet.h>

#ifdef RUNTIME_INTERPOSITION
#include <dlfcn.h>
#else
#include <unistd.h>
#endif

#define VIRTUAL_SOCKET_FD_ST 500

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
    startTCPService();
    
    if(domain != AF_INET || type != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP && protocol != IPPROTO_TCP)) {
#ifdef RUNTIME_INTERPOSITION
        int (*__real_socket)(int, int, int);
        __real_socket = (typeof(__real_socket))dlsym((void *)RTLD_NEXT, "socket");
        return __real_socket(domain, type, protocol);
#else
        return __real_socket(domain, type, protocol);
#endif
        // errno = EINVAL;
        // return -1;
    }
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
        fprintf(stderr, "[TCP Error] bind() only support IPv4\n");
        errno = EINVAL;
        return -1;
    }
    ret.ip = addr->sin_addr.s_addr;
    ret.port = ntohs(addr->sin_port);
    return 0;
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
    addr->sin_port = htons(s.port);
    *address_len = sizeof(struct sockaddr_in);
    return 0;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    fprintf(stderr, "__wrap_bind called\n");
    // https://man7.org/linux/man-pages/man7/ip.7.html

    if(socket < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_bind)(int, const struct sockaddr *, socklen_t);
        __real_bind = (typeof(__real_bind))dlsym((void *)RTLD_NEXT, "bind");
        return __real_bind(socket, address, address_len);
#else
        return __real_bind(socket, address, address_len);
#endif
    }
    
    std::scoped_lock lock(sockets_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (bind)\n");
        errno = EBADF;
        return -1;
    }
    
    SocketInfo &si = it->second;
    return system_to_socket_t(address, address_len, si.src);
}

static int finalize_socket_src(SocketInfo &si, bool isclient) {
    if(isclient && !si.src.ip) {
        si.src.ip = getAnyIP();
    }
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
    
    if(socket < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_listen)(int, int);
        __real_listen = (typeof(__real_listen))dlsym((void *)RTLD_NEXT, "listen");
        return __real_listen(socket, backlog);
#else
        return __real_listen(socket, backlog);
#endif
    }
    
    std::scoped_lock lock(sockets_mutex, pools_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (listen)\n");
        errno = EBADF;
        return -1;
    }

    SocketInfo &si = it->second;
    if(-1 == finalize_socket_src(si, false)) return -1;
    binds[si.src];
    si.type = SOCKET_TYPE_BIND;
    return 0;
}

int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
    if(socket < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_accept)(int, struct sockaddr *, socklen_t *);
        __real_accept = (typeof(__real_accept))dlsym((void *)RTLD_NEXT, "accept");
        return __real_accept(socket, address, address_len);
#else
        return __real_accept(socket, address, address_len);
#endif
    }
    
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (accept)\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_BIND) {
        fprintf(stderr, "[TCP Error] socket not listening\n");
        errno = EINVAL;
        return -1;
    }
    socket_t src = it->second.src;
    Bind &bind = binds[src];

    socket_t client_src, client;
    while(true) {
        lock_sockets.unlock();
        lock_pools.unlock();

        std::tie(client_src, client) = bind.q_socket.pop();
        
        std::lock(lock_sockets, lock_pools);
        Connection &conn = conns[std::make_pair(client_src, client)];
        lock_sockets.unlock();
        lock_pools.unlock();

        while(conn.status == STATUS_CLOSED ||
              conn.status == STATUS_SYN_SENT ||
              conn.status == STATUS_LISTEN ||
              conn.status == STATUS_SYN_RCVD) {
            conn.cond_socket.get();
        }
        if(conn.status == STATUS_TERMINATED) {
            // connection failed to establish
            conn.q_thread.push(free_connection);
            conn.thread_worker.join();

            lock_pools.lock();
            conns.erase(std::make_pair(client_src, client));
            lock_pools.unlock();
            continue;
        }
        
        if(-1 == socket_t_to_system(client, address, address_len)) {
            bind.q_socket.push(std::make_pair(client_src, client));
            // bad addr length, re-push it back..
            return -1;
        }
        break;
    }
    
    // create a new socket descriptor along with the connection.
    int id = nxt_vsock_fd++;
    sockets[id] = {SOCKET_TYPE_CONN, client_src, client};
    return id;
}

int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    if(socket < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_connect)(int, const struct sockaddr *, socklen_t);
        __real_connect = (typeof(__real_connect))dlsym((void *)RTLD_NEXT, "connect");
        return __real_connect(socket, address, address_len);
#else
        return __real_connect(socket, address, address_len);
#endif
    }

    std::unique_lock<std::mutex> lock(sockets_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (connect)\n");
        errno = EBADF;
        return -1;
    }
    SocketInfo &si = it->second;

    lock.unlock();
    if(-1 == system_to_socket_t(address, address_len, si.dest)) return -1;
    if(-1 == finalize_socket_src(si, true)) return -1;

    Connection &conn = init_connection(si.src, si.dest, STATUS_SYN_SENT);
    sendTCPSegment(si.src, si.dest, TH_SYN, conn.seq - 1, conn.ack, NULL, 0);
    while(true) {
        if(conn.status == STATUS_ESTAB ||
           conn.status == STATUS_CLOSE_WAIT) break;
        else if(conn.status == STATUS_TERMINATED) {
            conn.q_thread.push(free_connection);
            conn.thread_worker.join();

            std::scoped_lock lock2(pools_mutex);
            conns.erase(std::make_pair(si.src, si.dest));
            
            // note here we don't distinguish between ETIMEOUT and ECONNREFUSED
            errno = ECONNREFUSED;
            return -1;
        }
        conn.cond_socket.get();   // block to watch state change
    }

    lock.lock();
    si.type = SOCKET_TYPE_CONN;
    return 0;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbyte) {
    if(fd < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_read)(int, void *, size_t);
        __real_read = (typeof(__real_read))dlsym((void *)RTLD_NEXT, "read");
        return __real_read(fd, buf, nbyte);
#else
        return __real_read(fd, buf, nbyte);
#endif
    }
    
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(fd);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (read)\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_CONN){
        fprintf(stderr, "[TCP Error] socket is not an established connection\n");
        errno = EINVAL;
        return -1;
    }
    socket_t src = it->second.src, dest = it->second.dest;
    Connection &conn = conns[std::make_pair(src, dest)];

    lock_sockets.unlock();
    lock_pools.unlock();

    while(true) {
        std::unique_lock<std::mutex> lock_t(conn.conn_mutex);
        if(!conn.q_recv.empty()) {
            size_t i = 0;
            do {
                BufferSlice &bs = conn.q_recv.front();
                size_t read_len = std::min(bs.len - (conn.usrack - bs.seq), nbyte - i);
                memcpy((uint8_t *)buf + i, bs.mem.get() + conn.usrack - bs.seq, read_len);
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
        lock_t.unlock();
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
    if(fd < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        ssize_t (*__real_write)(int, const void *, size_t);
        __real_write = (typeof(__real_write))dlsym((void *)RTLD_NEXT, "write");
        return __real_write(fd, buf, nbyte);
#else
        return __real_write(fd, buf, nbyte);
#endif
    }
    
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(fd);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (write)\n");
        errno = EBADF;
        return -1;
    }
    if(it->second.type != SOCKET_TYPE_CONN){
        fprintf(stderr, "[TCP Error] socket is not an established connection\n");
        errno = EINVAL;
        return -1;
    }
    socket_t src = it->second.src, dest = it->second.dest;
    Connection &conn = conns[std::make_pair(src, dest)];

    lock_sockets.unlock();
    lock_pools.unlock();

    if(conn.status == STATUS_FIN_WAIT_1 || conn.status == STATUS_FIN_WAIT_2 ||
       conn.status == STATUS_TERMINATED) {
        errno = EPIPE;  // NOTIMPLEMENTED: no sigpipe sent.
        return 0;     // client side already closed. in fact, only TERMINATED is expected in current implementation.
    }

    // NOTIMPLEMENTED: no any form of window. all data are sent at once, congesting the network at the furthest possible.

    size_t i = 0;
    while(i < nbyte) {
        std::unique_lock<std::mutex> lock_t(conn.conn_mutex);
        size_t len = std::min(nbyte - i, (size_t)TCP_DATA_MTU);
        conn.q_sent.push(BufferSlice{std::shared_ptr<uint8_t[]>(new uint8_t[len]),
                    conn.seq, len, {}});
        BufferSlice &bs = conn.q_sent.back();
        lock_t.unlock();
        memcpy(bs.mem.get(), (const uint8_t *)buf + i, len);
        do_transmit(bs, src, dest, conn);
        conn.seq += len;
        i += len;
    }
    return nbyte;
}

int __wrap_close(int socket) {
    if(socket < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        int (*__real_close)(int);
        __real_close = (typeof(__real_close))dlsym((void *)RTLD_NEXT, "close");
        return __real_close(socket);
#else
        return __real_close(socket);
#endif
    }
    
    std::unique_lock<std::mutex> lock_sockets(sockets_mutex, std::defer_lock);
    std::unique_lock<std::mutex> lock_pools(pools_mutex, std::defer_lock);
    std::lock(lock_sockets, lock_pools);
    
    auto it = sockets.find(socket);
    if(it == sockets.end()) {
        fprintf(stderr, "[TCP Error] socket fd invalid (close)\n");
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
    conn.q_thread.push(tcp_call_close);

    while(conn.status != STATUS_TERMINATED) {
        conn.cond_socket.get();    // block until another change.
    }
    conn.q_thread.push(free_connection);
    conn.thread_worker.join();
    
    lock_pools.lock();
    conns.erase(std::make_pair(src, dest));
    lock_pools.unlock();

    lock_sockets.lock();
    sockets.erase(it);
    return 0;
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    if(hints &&
       ((hints->ai_family != AF_INET && hints->ai_family != AF_UNSPEC) ||
        (hints->ai_socktype && hints->ai_socktype != SOCK_STREAM) ||
        (hints->ai_protocol && hints->ai_protocol != IPPROTO_TCP))) {
        // we don't support this kind of request
        return EAI_SERVICE;
    }
    
    struct sockaddr_in *addr = new struct sockaddr_in;
    addr->sin_family = AF_INET;
    if(service) addr->sin_port = htons(atoi(service)); else addr->sin_port = 0;
    if(node) {
        if(inet_aton(node, &addr->sin_addr) == 0) {
            fprintf(stderr, "[TCP Error] IP parse failed: %s\n", node);
            return EAI_NONAME;
        }
    }
    else addr->sin_addr.s_addr = 0;
    
    struct addrinfo *ret = new struct addrinfo;
    ret->ai_flags = (addr->sin_addr.s_addr == 0 ? AI_PASSIVE : 0);
    ret->ai_family = AF_INET;
    ret->ai_socktype = SOCK_STREAM;
    ret->ai_protocol = IPPROTO_TCP;
    ret->ai_addrlen = sizeof(struct sockaddr_in);
    ret->ai_addr = (struct sockaddr *)addr;
    ret->ai_canonname = NULL;
    ret->ai_next = NULL;

    *res = ret;
    return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *res) {
    delete res->ai_addr;
    delete res;
}

ssize_t __wrap_send(int sockfd, const void *buf, size_t len, int flags) {
    return __wrap_write(sockfd, buf, len);
}

ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    return __wrap_write(sockfd, buf, len);
}

ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags) {
    return __wrap_read(sockfd, buf, len);
}

ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    return __wrap_read(sockfd, buf, len);
}

int __wrap_setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen) {
    if(sockfd < VIRTUAL_SOCKET_FD_ST) {
#ifdef RUNTIME_INTERPOSITION
        int (*__real_setsockopt)(int, int, int, const void *, socklen_t);
        __real_setsockopt = (typeof(__real_setsockopt))dlsym((void *)RTLD_NEXT, "setsockopt");
        return __real_setsockopt(sockfd, level, optname, optval, optlen);
#else
        return __real_setsockopt(sockfd, level, optname, optval, optlen);
#endif
    }
    return 0;  // ignore all options.
}
