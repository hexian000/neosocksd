/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sockutil.h"
#include "proto/domain.h"
#include "util.h"

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

#include <inttypes.h>
#include <limits.h>
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
		const int err = errno;
		LOGW_F("SO_REUSEADDR: %s", strerror(err));
	}
#ifdef SO_REUSEPORT
	val = reuseport ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("SO_REUSEPORT: %s", strerror(err));
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
		const int err = errno;
		LOGW_F("TCP_NODELAY: %s", strerror(err));
	}
	val = keepalive ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("SO_KEEPALIVE: %s", strerror(err));
	}
}

void socket_set_fastopen(const int fd, const int backlog)
{
#ifdef TCP_FASTOPEN
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog))) {
		const int err = errno;
		LOGW_F("TCP_FASTOPEN: %s", strerror(err));
	}
#else
	UNUSED(fd);
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
		const int err = errno;
		LOGW_F("TCP_FASTOPEN_CONNECT: %s", strerror(err));
	}
#else
	UNUSED(fd);
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
			const int err = errno;
			LOGW_F("SO_SNDBUF: %s", strerror(err));
		}
	}
	if (recv > 0) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv, sizeof(recv))) {
			const int err = errno;
			LOGW_F("SO_RCVBUF: %s", strerror(err));
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
		const int err = errno;
		LOGW_F("SO_BINDTODEVICE: %s", strerror(err));
	}
#else
	UNUSED(fd);
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
		const int err = errno;
		/* this is a fatal error */
		FAILMSGF("IP_TRANSPARENT: %s", strerror(err));
	}
#else
	UNUSED(fd);
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
		const int err = errno;
		LOGW_F("SO_RCVLOWAT: %s", strerror(err));
	}
}

int socket_get_error(const int fd)
{
	int value = 0;
	socklen_t len = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &len)) {
		const int err = errno;
		LOGW_F("SO_ERROR: %s", strerror(err));
	}
	return value;
}

socklen_t getsocklen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		break;
	}
	FAIL();
}

static int
format_sa_inet(const struct sockaddr_in *sa, char *buf, const size_t buf_size)
{
	char s[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(sa->sin_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin_port);
	return snprintf(buf, buf_size, "%s:%" PRIu16, s, port);
}

static int
format_sa_inet6(const struct sockaddr_in6 *sa, char *buf, const size_t buf_size)
{
	char s[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(sa->sin6_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin6_port);
	const uint32_t scope = sa->sin6_scope_id;
	if (scope == 0) {
		return snprintf(buf, buf_size, "[%s]:%" PRIu16, s, port);
	}
	return snprintf(
		buf, buf_size, "[%s%%%" PRIu32 "]:%" PRIu16, s, scope, port);
}

int format_sa(const struct sockaddr *sa, char *buf, const size_t buf_size)
{
	switch (sa->sa_family) {
	case AF_INET:
		return format_sa_inet((struct sockaddr_in *)sa, buf, buf_size);
	case AF_INET6:
		return format_sa_inet6(
			(struct sockaddr_in6 *)sa, buf, buf_size);
	default:
		break;
	}
	return snprintf(buf, buf_size, "<af:%jd>", (intmax_t)sa->sa_family);
}

static bool find_addrinfo(union sockaddr_max *sa, const struct addrinfo *it)
{
	for (; it != NULL; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in));
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in6));
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
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
			LOGE_F("send: fd=%d %s", fd, strerror(err));
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
	LOGV_F("send: fd=%d %zu bytes", fd, nbsend);
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
			LOGE_F("recv: fd=%d %s", fd, strerror(err));
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
	LOGV_F("recv: fd=%d %zu bytes", fd, nbrecv);
	return 0;
}
