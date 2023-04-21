/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>

typedef union {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} sockaddr_max_t;

bool socket_set_nonblock(int fd);
void socket_set_reuseport(int fd, bool reuseport);
void socket_set_tcp(int fd, bool nodelay, bool keepalive);
void socket_set_buffer(int fd, size_t send, size_t recv);
void socket_bind_netdev(int fd, const char *netdev);
void socket_set_tproxy(int fd, bool tproxy);

socklen_t getsocklen(const struct sockaddr *sa);
int format_sa(const struct sockaddr *sa, char *s, size_t buf_size);

bool parse_bindaddr(sockaddr_max_t *sa, const char *s);
bool resolve_hostname(sockaddr_max_t *sa, const char *host, int family);

#endif /* SOCKUTIL_H */
