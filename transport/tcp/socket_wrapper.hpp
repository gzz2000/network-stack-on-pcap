#pragma once

/** 
 * @file socket_wrapper.hpp
 * @brief POSIX-compatible socket library supporting TCP protocol on IPv4.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef RUNTIME_INTERPOSITION
#define __wrap_socket socket
#define __wrap_bind bind
#define __wrap_listen listen
#define __wrap_connect connect
#define __wrap_accept accept
#define __wrap_read read
#define __wrap_write write
#define __wrap_close close
#define __wrap_getaddrinfo getaddrinfo
#define __wrap_freeaddrinfo freeaddrinfo
#else
extern "C" {

ssize_t __real_read(int, void *, size_t);
ssize_t __real_write(int, const void *, size_t);
int __real_close(int);

}
#endif

extern "C" {

/**
 * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/socket.html)
 */
int __wrap_socket(int domain, int type, int protocol);

/**
 * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/bind.html)
 */
int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);
 
/**
 * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/listen.html)
 */
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/connect.html)
 */
int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

/**
 * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/accept.html)
 */
int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

/**
 * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/read.html)
 */
ssize_t __wrap_read(int fd, void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/write.html)
 */
ssize_t __wrap_write(int fd, const void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/close.html)
 */
int __wrap_close(int fd);

/** 
 * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/getaddrinfo.html)
 */
int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

void __wrap_freeaddrinfo(struct addrinfo *res);

}  // extern "C"
