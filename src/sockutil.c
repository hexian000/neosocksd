/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sockutil.h"

#include "proto/domain.h"

#include "net/addr.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool socket_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_CLOEXEC | O_NONBLOCK) != -1;
}

void socket_set_reuseport(const int fd, const bool reuseport)
{
	int val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
		LOGW_F("SO_REUSEADDR: %s", strerror(errno));
	}
#ifdef SO_REUSEPORT
	val = reuseport ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val))) {
		LOGW_F("SO_REUSEPORT: %s", strerror(errno));
	}
#else
	if (reuseport) {
		LOGW_F("SO_REUSEPORT: %s", "not supported in current build");
	}
#endif
}

void socket_set_tcp(const int fd, const bool nodelay, const bool keepalive)
{
	int val;
	val = nodelay ? 1 : 0;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val))) {
		LOGW_F("TCP_NODELAY: %s", strerror(errno));
	}
	val = keepalive ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val))) {
		LOGW_F("SO_KEEPALIVE: %s", strerror(errno));
	}
}

void socket_set_fastopen(const int fd, const int backlog)
{
#ifdef TCP_FASTOPEN
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog))) {
		LOGW_F("TCP_FASTOPEN: %s", strerror(errno));
	}
#else
	(void)fd;
	if (backlog > 0) {
		LOGW_F("TCP_FASTOPEN: %s", "not supported in current build");
	}
#endif
}

void socket_set_fastopen_connect(const int fd, const bool enabled)
{
#ifdef TCP_FASTOPEN_CONNECT
	int val = enabled ? 1 : 0;
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &val, sizeof(val))) {
		LOGW_F("TCP_FASTOPEN_CONNECT: %s", strerror(errno));
	}
#else
	(void)fd;
	if (enabled) {
		LOGW_F("TCP_FASTOPEN_CONNECT: %s",
		       "not supported in current build");
	}
#endif
}

void socket_set_buffer(const int fd, int send, int recv)
{
	if (send > 0) {
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send, sizeof(send))) {
			LOGW_F("SO_SNDBUF: %s", strerror(errno));
		}
	}
	if (recv > 0) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv, sizeof(recv))) {
			LOGW_F("SO_RCVBUF: %s", strerror(errno));
		}
	}
}

void socket_bind_netdev(const int fd, const char *netdev)
{
#ifdef SO_BINDTODEVICE
	char ifname[IFNAMSIZ];
	(void)strncpy(ifname, netdev, sizeof(ifname) - 1);
	ifname[sizeof(ifname) - 1] = '\0';
	if (setsockopt(
		    fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname))) {
		LOGW_F("SO_BINDTODEVICE: %s", strerror(errno));
	}
#else
	(void)fd;
	if (netdev[0] != '\0') {
		LOGW_F("SO_BINDTODEVICE: %s", "not supported in current build");
	}
#endif
}

void socket_set_transparent(const int fd, const bool tproxy)
{
#ifdef IP_TRANSPARENT
	int val = tproxy ? 1 : 0;
	if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &val, sizeof(val))) {
		/* this is a fatal error */
		FAILMSGF("IP_TRANSPARENT: %s", strerror(errno));
	}
#else
	(void)fd;
	CHECKMSGF(
		!tproxy, "IP_TRANSPARENT: %s",
		"not supported in current build");
#endif
}

void socket_rcvlowat(const int fd, const size_t bytes)
{
	CHECK(0 < bytes && bytes <= INT_MAX);
	const int value = (int)bytes;
	socklen_t len = sizeof(value);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, len)) {
		LOGW_F("SO_RCVLOWAT: %s", strerror(errno));
	}
}

int socket_get_error(const int fd)
{
	int value = 0;
	socklen_t len = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &len)) {
		LOGW_F("SO_ERROR: %s", strerror(errno));
	}
	return value;
}

socklen_t getsocklen(const struct sockaddr *restrict sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		break;
	}
	FAILMSGF("unexpected af: %jd", (intmax_t)sa->sa_family);
}

void copy_sa(struct sockaddr *restrict dst, const struct sockaddr *restrict src)
{
	switch (src->sa_family) {
	case AF_INET:
		*(struct sockaddr_in *)dst = *(const struct sockaddr_in *)src;
		return;
	case AF_INET6:
		*(struct sockaddr_in6 *)dst = *(const struct sockaddr_in6 *)src;
		return;
	default:
		break;
	}
	FAILMSGF("unexpected af: %jd", (intmax_t)src->sa_family);
}

static int
format_sa_inet(char *s, const size_t maxlen, const struct sockaddr_in *sa)
{
	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(sa->sin_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin_port);
	return snprintf(s, maxlen, "%s:%" PRIu16, buf, port);
}

static int
format_sa_inet6(char *s, const size_t maxlen, const struct sockaddr_in6 *sa)
{
	char buf[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(sa->sin6_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin6_port);
	const uint32_t scope = sa->sin6_scope_id;
	if (scope == 0) {
		return snprintf(s, maxlen, "[%s]:%" PRIu16, buf, port);
	}
	return snprintf(
		s, maxlen, "[%s%%%" PRIu32 "]:%" PRIu16, buf, scope, port);
}

int format_sa(char *s, const size_t maxlen, const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return format_sa_inet(s, maxlen, (struct sockaddr_in *)sa);
	case AF_INET6:
		return format_sa_inet6(s, maxlen, (struct sockaddr_in6 *)sa);
	default:
		break;
	}
	return snprintf(s, maxlen, "<af:%jd>", (intmax_t)sa->sa_family);
}

static bool find_addrinfo(union sockaddr_max *sa, const struct addrinfo *node)
{
	for (const struct addrinfo *it = node; it != NULL; it = it->ai_next) {
#define EXPECT_ADDRLEN(p, expected)                                            \
	do {                                                                   \
		if ((p)->ai_addrlen != (expected)) {                           \
			LOGE_F("getaddrinfo: invalid ai_addrlen %ju (af=%d)",  \
			       (uintmax_t)(p)->ai_addrlen, (p)->ai_family);    \
			continue;                                              \
		}                                                              \
	} while (0)

		switch (it->ai_family) {
		case AF_INET:
			EXPECT_ADDRLEN(it, sizeof(struct sockaddr_in));
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			EXPECT_ADDRLEN(it, sizeof(struct sockaddr_in6));
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}

#undef EXPECT_ADDRLEN
		return true;
	}
	return false;
}

bool parse_bindaddr(union sockaddr_max *sa, const char *s)
{
	const size_t addrlen = strlen(s);
	char buf[FQDN_MAX_LENGTH + 1 + 5 + 1];
	if (addrlen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, s, addrlen);
	buf[addrlen] = '\0';
	char *hoststr, *portstr;
	if (!splithostport(buf, &hoststr, &portstr)) {
		return false;
	}
	if (hoststr[0] == '\0') {
		hoststr = NULL;
	}
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(hoststr, portstr, &hints, &result);
	if (err != 0) {
		LOGE_F("resolve: %s", gai_strerror(err));
		return false;
	}
	const bool ok = find_addrinfo(sa, result);
	freeaddrinfo(result);
	return ok;
}

bool resolve_addr(
	union sockaddr_max *sa, const char *name, const char *service,
	const int family)
{
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_ADDRCONFIG,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(name, service, &hints, &result);
	if (err != 0) {
		LOGE_F("resolve: %s", gai_strerror(err));
		return false;
	}
	const bool ok = find_addrinfo(sa, result);
	freeaddrinfo(result);
	return ok;
}

int socket_send(const int fd, const void *buf, size_t *len)
{
	const unsigned char *b = buf;
	size_t nbsend = 0;
	size_t n = *len;
	while (n > 0) {
		const ssize_t nsend = send(fd, b, n, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			*len = nbsend;
			return err;
		}
		if (nsend == 0) {
			break;
		}
		b += nsend;
		n -= nsend;
		nbsend += nsend;
	}
	*len = nbsend;
	return 0;
}

int socket_recv(const int fd, void *buf, size_t *len)
{
	unsigned char *b = buf;
	size_t nbrecv = 0;
	size_t n = *len;
	while (n > 0) {
		const ssize_t nrecv = recv(fd, b, n, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			*len = nbrecv;
			return err;
		}
		if (nrecv == 0) {
			break;
		}
		b += nrecv;
		n -= nrecv;
		nbrecv += nrecv;
	}
	*len = nbrecv;
	return 0;
}
