/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

/* Check if the error is generally "transient":
 *   In accept()/send()/recv()/sendmsg()/recvmsg()/sendmmsg()/recvmmsg(),
 * transient errors should not cause the socket to fail. The operation should
 * be retried later if the corresponding event is still available.
 */
#define IS_TRANSIENT_ERROR(err)                                                \
	((err) == EINTR || (err) == EAGAIN || (err) == EWOULDBLOCK ||          \
	 (err) == ENOBUFS || (err) == ENOMEM)

union sockaddr_max {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

bool socket_set_nonblock(int fd);
void socket_set_reuseport(int fd, bool reuseport);
void socket_set_tcp(int fd, bool nodelay, bool keepalive);
void socket_set_fastopen(int fd, int backlog);
void socket_set_fastopen_connect(int fd, bool enabled);
void socket_set_buffer(int fd, int send, int recv);
void socket_bind_netdev(int fd, const char *netdev);
void socket_set_transparent(int fd, bool tproxy);
void socket_rcvlowat(int fd, size_t bytes);
int socket_get_error(int fd);

socklen_t getsocklen(const struct sockaddr *sa);
void copy_sa(struct sockaddr *dst, const struct sockaddr *src);
int format_sa(char *s, size_t maxlen, const struct sockaddr *sa);

bool parse_bindaddr(union sockaddr_max *sa, const char *s);
bool resolve_addr(
	union sockaddr_max *sa, const char *name, const char *service,
	int family);

int socket_send(int fd, const void *buf, size_t *len);
int socket_recv(int fd, void *buf, size_t *len);

#endif /* SOCKUTIL_H */
