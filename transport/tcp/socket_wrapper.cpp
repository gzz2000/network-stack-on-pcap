#include "socket_wrapper.hpp"
#include "tcp_internal.hpp"
#include "config.hpp"
#include "service.hpp"
#include "link/ethernet/device.hpp"
#include "ip/ip.hpp"
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <arpa/inet.h>

#ifdef RUNTIME_INTERPOSITION
#include <dlfcn.h>

int (*__real_socket)(int, int, int);
ssize_t (*__real_bind)(int, const struct sockaddr *, socklen_t);
ssize_t (*__real_listen)(int, int);
ssize_t (*__real_accept)(int, struct sockaddr *, socklen_t *);
ssize_t (*__real_connect)(int, const struct sockaddr *, socklen_t);
ssize_t (*__real_read)(int, void *, size_t);
ssize_t (*__real_write)(int, const void *, size_t);
int (*__real_close)(int);
int (*__real_setsockopt)(int, int, int, const void *, socklen_t);
int (*__real_getsockname)(int, struct sockaddr *, socklen_t *);

static bool is_real_inited;

void init_reals() {
    if(is_real_inited) return;
    is_real_inited = true;
    
    __real_socket = (typeof(__real_socket))dlsym((void *)RTLD_NEXT, "socket");
    __real_bind = (typeof(__real_bind))dlsym((void *)RTLD_NEXT, "bind");
    __real_listen = (typeof(__real_listen))dlsym((void *)RTLD_NEXT, "listen");
    __real_accept = (typeof(__real_accept))dlsym((void *)RTLD_NEXT, "accept");
    __real_connect = (typeof(__real_connect))dlsym((void *)RTLD_NEXT, "connect");
    __real_read = (typeof(__real_read))dlsym((void *)RTLD_NEXT, "read");
    __real_write = (typeof(__real_write))dlsym((void *)RTLD_NEXT, "write");
    __real_close = (typeof(__real_close))dlsym((void *)RTLD_NEXT, "close");
    __real_setsockopt = (typeof(__real_setsockopt))dlsym((void *)RTLD_NEXT, "setsockopt");
    __real_getsockname = (typeof(__real_getsockname))dlsym((void *)RTLD_NEXT, "getsockname");
}
#else
#include <unistd.h>
#endif

enum socket_type {
    SOCKET_TYPE_IDLE = 0,
    SOCKET_TYPE_BIND,
    SOCKET_TYPE_CONN,
};

struct SocketInfo {
    socket_type type;
    socket_t src, dest;
    int sv[2];
    std::thread thread_writebuf;
};

std::mutex sockets_mutex;
std::unordered_map<int, SocketInfo> sockets;

static void thread_write_buf_monitor(int readfd, socket_t src, socket_t dest, Connection &conn);

int __wrap_socket(int domain, int type, int protocol) {
    // fprintf(stderr, "__wrap_socket called, domain=%d,type=%d,protocol=%d\n",
    //         domain, type, protocol);
    startTCPService();

    if(domain == AF_INET6) {
        fprintf(stderr, "blocking ipv6 socket creation\n");
        return -1;
    }
    
    if(domain != AF_INET || (type & SOCK_STREAM) != SOCK_STREAM ||
       (protocol && protocol != IPPROTO_TCP && protocol != IPPROTO_IP)) {
#ifdef RUNTIME_INTERPOSITION
        init_reals();
#endif
        return __real_socket(domain, type, protocol);
        // errno = EINVAL;
        // return -1;
    }

    int sv[2];
    if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) return -1;
    
    std::scoped_lock lock(sockets_mutex);
    sockets[sv[0]] = {SOCKET_TYPE_IDLE, {0, 0}, {0, 0}, {sv[0], sv[1]}, {}};
    fprintf(stderr, "__wrap_socket returned special socket %d\n", sv[0]);
    return sv[0];
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

static SocketInfo *find_socket(int socket) {
    std::scoped_lock lock(sockets_mutex);
    auto it = sockets.find(socket);
    if(it == sockets.end()) return NULL;
    else return &it->second;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    // https://man7.org/linux/man-pages/man7/ip.7.html

    SocketInfo *psi = find_socket(socket);

    if(!psi) {
#ifdef RUNTIME_INTERPOSITION
        init_reals();
#endif
        return __real_bind(socket, address, address_len);
    }
    
    return system_to_socket_t(address, address_len, psi->src);
}

static int finalize_socket_src(SocketInfo &si, bool isclient) {
    static int nxt_port_to_search = 32769;
    
    std::scoped_lock lock(pools_mutex);
    if(isclient && !si.src.ip) {
        si.src.ip = getAnyIP();
    }
    if(!si.src.port) {
        // choose an ephemeral address from 32769 to 60999
        si.src.port = nxt_port_to_search;
        while(binds.count(si.src)) {
            ++si.src.port;
            if(si.src.port == 61000u) si.src.port = 32769u;
            if(si.src.port == nxt_port_to_search) {
                // no ephemeral port available
                errno = EADDRINUSE;
                return -1;
            }
        }
        nxt_port_to_search = si.src.port + 1;
        if(nxt_port_to_search == 61000u) nxt_port_to_search = 32769u;
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
    
    SocketInfo *psi = find_socket(socket);
    
    if(!psi) {
#ifdef RUNTIME_INTERPOSITION
        init_reals();
#endif
        return __real_listen(socket, backlog);
    }
    
    if(-1 == finalize_socket_src(*psi, false)) return -1;

    std::scoped_lock lock(pools_mutex);
    binds[psi->src].q_socket_fd = psi->sv[1];   // create bind
    psi->type = SOCKET_TYPE_BIND;
    return 0;
}

// static Bind *find_bind(socket_t src) {
//     std::scoped_lock lock(pools_mutex);
//     auto it = binds.find(src);
//     if(it == binds.end()) return NULL;
//     return &it->second;
// }

static Connection *find_connection(socket_t src, socket_t dest) {
    std::scoped_lock lock(pools_mutex);
    auto it = conns.find(std::make_pair(src, dest));
    if(it == conns.end()) return NULL;
    return &it->second;
}

static int read_acc(int fd, socket_accept_t &pair) {
    uint8_t *pair_b = (uint8_t *)&pair; int len_pair_read = 0;

    while(true) {
        ssize_t ret = __real_read(fd, pair_b, sizeof(socket_accept_t) - len_pair_read);
        if(ret < 0) continue;
        if(ret == 0) return -1;
        len_pair_read += ret;
        pair_b += ret;
        if(len_pair_read == sizeof(socket_accept_t)) break;
    }
    return 0;
}

int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
    SocketInfo *psi = find_socket(socket);
    
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    if(!psi) {
        return __real_accept(socket, address, address_len);
    }
    
    if(psi->type != SOCKET_TYPE_BIND) {
        fprintf(stderr, "[TCP Error] socket not listening\n");
        errno = EINVAL;
        return -1;
    }
    
    // Bind *pb = find_bind(psi->src);
    socket_accept_t pair;

    if(read_acc(socket, pair) < 0) {
        fprintf(stderr, "[TCP Error] accept discovers EOF\n");
        errno = ECONNABORTED;
        return -1;
    }

    // socket_t client_src = pair.a, client = pair.b;
    Connection &conn = *find_connection(pair.a, pair.b);
    
    while(conn.status == STATUS_CLOSED ||
          conn.status == STATUS_SYN_SENT ||
          conn.status == STATUS_LISTEN ||
          conn.status == STATUS_SYN_RCVD) {
        conn.cond_socket.get();
    }
    
    if(-1 == socket_t_to_system(pair.b, address, address_len)) {
        fprintf(stderr, "[TCP Error] bad address_len. leaking a connection!!");
        return -1;
    }
    
    std::scoped_lock lock(sockets_mutex);
    sockets[pair.sv[0]] = {SOCKET_TYPE_CONN, pair.a, pair.b, {pair.sv[0], pair.sv[1]},
                           std::thread(thread_write_buf_monitor, pair.sv[1], pair.a, pair.b, std::ref(conn))};
    return pair.sv[0];
}

int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    SocketInfo *psi = find_socket(socket);
    if(!psi) {
        return __real_connect(socket, address, address_len);
    }
    SocketInfo &si = *psi;

    if(-1 == system_to_socket_t(address, address_len, si.dest)) return -1;
    if(-1 == finalize_socket_src(si, true)) return -1;

    std::unique_lock<std::mutex> lock(pools_mutex);
    Connection &conn = init_connection(si.src, si.dest, si.sv[1], STATUS_SYN_SENT);
    lock.unlock();
    sendTCPSegment(si.src, si.dest, TH_SYN, conn.seq - 1, conn.ack, NULL, 0);
    
    while(true) {
        if(conn.status == STATUS_ESTAB ||
           conn.status == STATUS_CLOSE_WAIT) break;
        else if(conn.status == STATUS_TERMINATED) {
            conn.q_thread.push(free_connection);
            conn.thread_worker.join();
            
            lock.lock();
            conns.erase(std::make_pair(si.src, si.dest));
            
            // note here we don't distinguish between ETIMEOUT and ECONNREFUSED
            errno = ECONNREFUSED;
            return -1;
        }
        conn.cond_socket.get();   // block to watch state change
    }

    si.type = SOCKET_TYPE_CONN;
    si.thread_writebuf = std::thread(thread_write_buf_monitor, si.sv[1], si.src, si.dest, std::ref(conn));
    return 0;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbyte) {
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    return __real_read(fd, buf, nbyte);
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

static void thread_write_buf_monitor(int readfd, socket_t src, socket_t dest, Connection &conn) {
    uint8_t buf[TCP_DATA_MTU];
    // NOTIMPLEMENTED: no any form of window. all data are sent at once, congesting the network at the furthest possible.
    while(true) {
        ssize_t len = __real_read(readfd, buf, TCP_DATA_MTU);
        if(len < 0) continue;
        if(len == 0) break;
        std::unique_lock<std::mutex> lock_t(conn.conn_mutex);
        
        if(conn.status == STATUS_FIN_WAIT_1 || conn.status == STATUS_FIN_WAIT_2 ||
           conn.status == STATUS_TERMINATED) {
            // previously implemented in __wrap_write
            // now not possible. but we can signal this perhaps using syscall
            return;
            // errno = EPIPE;  // NOTIMPLEMENTED: no sigpipe sent.
            // return 0;     // client side already closed. in fact, only TERMINATED is expected in current implementation.
        }
        
        conn.q_sent.push(BufferSlice{std::shared_ptr<uint8_t[]>(new uint8_t[len]),
                    conn.seq, (size_t)len, {}});
        BufferSlice &bs = conn.q_sent.back();
        memcpy(bs.mem.get(), buf, len);
        conn.seq += len;
        lock_t.unlock();
        do_transmit(bs, src, dest, conn);
    }
    conn.q_thread.push(tcp_call_close);   // close connection once write is finished with EOF (close is called)
}

ssize_t __wrap_write(int fd, const void *buf, size_t nbyte) {
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    return __real_write(fd, buf, nbyte);
}

int __wrap_close(int socket) {
#ifdef RUNTIME_INTERPOSITION
    init_reals();
#endif
    
    SocketInfo *psi = find_socket(socket);
    if(!psi) {
        return __real_close(socket);
    }

    if(psi->type == SOCKET_TYPE_IDLE) {
        __real_close(psi->sv[0]);
        __real_close(psi->sv[1]);
    }
    else if(psi->type == SOCKET_TYPE_BIND) {
        {   // manually remove the bind item
            std::scoped_lock lock(pools_mutex);
            binds.erase(psi->src);
        }
        
        __real_close(psi->sv[0]);
        __real_close(psi->sv[1]);
    }
    else {
        // else: psi->type == SOCKET_TYPE_CONN
        
        socket_t src = psi->src, dest = psi->dest;
        Connection &conn = *find_connection(src, dest);

        conn.q_socket_fd = 0;
        __real_close(psi->sv[0]);
        psi->thread_writebuf.join();
        
        while(conn.status != STATUS_TERMINATED) {
            conn.cond_socket.get();    // block until another change.
        }
        __real_close(psi->sv[1]);
        conn.q_thread.push(free_connection);
        conn.thread_worker.join();
        
        std::scoped_lock lock(pools_mutex);
        conns.erase(std::make_pair(src, dest));
    }

    std::scoped_lock lock(sockets_mutex);
    sockets.erase(sockets.find(socket));
    return 0;
}

// int __wrap_getaddrinfo(const char *node, const char *service,
//                        const struct addrinfo *hints,
//                        struct addrinfo **res) {
//     fprintf(stderr, "__wrap_getaddrinfo called\n");
//     if(hints &&
//             ((hints->ai_family != AF_INET && hints->ai_family != AF_UNSPEC) ||
//             (hints->ai_socktype && (hints->ai_socktype & SOCK_STREAM) != SOCK_STREAM))) {
//         // we don't support this kind of request
//         return EAI_SERVICE;
//     }
    
//     struct sockaddr_in *addr = new struct sockaddr_in;
//     addr->sin_family = AF_INET;
//     if(service) addr->sin_port = htons(atoi(service)); else addr->sin_port = 0;
//     if(node) {
//         if(inet_aton(node, &addr->sin_addr) == 0) {
//             fprintf(stderr, "[TCP Error] IP parse failed: %s\n", node);
//             return EAI_NONAME;
//         }
//     }
//     else addr->sin_addr.s_addr = 0;
    
//     struct addrinfo *ret = new struct addrinfo;
//     ret->ai_flags = (addr->sin_addr.s_addr == 0 ? AI_PASSIVE : 0);
//     ret->ai_family = AF_INET;
//     ret->ai_socktype = SOCK_STREAM;
//     ret->ai_protocol = IPPROTO_TCP;
//     ret->ai_addrlen = sizeof(struct sockaddr_in);
//     ret->ai_addr = (struct sockaddr *)addr;
//     ret->ai_canonname = NULL;
//     ret->ai_next = NULL;

//     *res = ret;
//     return 0;
// }

// void __wrap_freeaddrinfo(struct addrinfo *res) {
//     delete res->ai_addr;
//     delete res;
// }

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
    SocketInfo *psi = find_socket(sockfd);
    if(!psi) {
#ifdef RUNTIME_INTERPOSITION
        init_reals();
#endif
        return __real_setsockopt(sockfd, level, optname, optval, optlen);
    }
    return 0;  // ignore all options.
}

int __wrap_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    SocketInfo *psi = find_socket(sockfd);
    if(!psi) {
#ifdef RUNTIME_INTERPOSITION
        init_reals();
#endif
        return __real_getsockname(sockfd, addr, addrlen);
    }
    
    if(-1 == socket_t_to_system(psi->src, addr, addrlen)) {
        fprintf(stderr, "[TCP Error] bad address_len.");
        return -1;
    }
    return 0;
}
