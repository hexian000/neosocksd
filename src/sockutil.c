/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sockutil.h"
#include "net/addr.h"
#include "utils/minmax.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "resolver.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

bool socket_set_nonblock(int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_CLOEXEC | O_NONBLOCK) != -1;
}

void socket_set_reuseport(const int fd, const bool reuseport)
{
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_REUSEADDR: %s", strerror(err));
	}
#ifdef SO_REUSEPORT
	if (setsockopt(
		    fd, SOL_SOCKET, SO_REUSEPORT, &(int){ reuseport ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_REUSEPORT: %s", strerror(err));
	}
#else
	if (reuseport) {
		LOGW("reuseport: not supported in current build");
	}
#endif
}

void socket_set_tcp(const int fd, const bool nodelay, const bool keepalive)
{
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_NODELAY, &(int){ nodelay ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("TCP_NODELAY: %s", strerror(err));
	}
	if (setsockopt(
		    fd, SOL_SOCKET, SO_KEEPALIVE, &(int){ keepalive ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_KEEPALIVE: %s", strerror(err));
	}
}

void socket_set_buffer(int fd, size_t send, size_t recv)
{
	int val;
	if (send > 0) {
		val = (int)MIN(send, INT_MAX);
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val))) {
			const int err = errno;
			LOGW_F("SO_SNDBUF: %s", strerror(err));
		}
	}
	if (recv > 0) {
		val = (int)MIN(recv, INT_MAX);
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val))) {
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
	if (setsockopt(
		    fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname))) {
		const int err = errno;
		LOGW_F("SO_BINDTODEVICE: %s", strerror(err));
	}
#else
	UNUSED(fd);
	UNUSED(netdev);
	LOGW("netdev: not supported in current build");
#endif
}

void socket_set_tproxy(int fd, bool tproxy)
{
#ifdef IP_TRANSPARENT
	if (setsockopt(
		    fd, SOL_IP, IP_TRANSPARENT, &(int){ tproxy ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		/* this is a fatal error */
		FAILMSGF("IP_TRANSPARENT: %s", strerror(err));
	}
#else
	UNUSED(fd);
	CHECKMSG(!tproxy, "tproxy: not supported in current build");
#endif
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
	LOGF("only IPv4/IPv6 addresses are supported");
	abort();
}

static int
format_sa_inet(const struct sockaddr_in *addr, char *buf, const size_t buf_size)
{
	char s[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(addr->sin_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(addr->sin_port);
	return snprintf(buf, buf_size, "%s:%" PRIu16, s, port);
}

static int format_sa_inet6(
	const struct sockaddr_in6 *addr, char *buf, const size_t buf_size)
{
	char s[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(addr->sin6_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(addr->sin6_port);
	const uint32_t scope = addr->sin6_scope_id;
	if (scope == 0) {
		return snprintf(buf, buf_size, "[%s]:%" PRIu16, s, port);
	}
	return snprintf(
		buf, buf_size, "[%s%%%" PRIu32 "]:%" PRIu16, s, scope, port);
}

int format_sa(const struct sockaddr *sa, char *buf, const size_t buf_size)
{
	int ret = -1;
	switch (sa->sa_family) {
	case AF_INET:
		ret = format_sa_inet((struct sockaddr_in *)sa, buf, buf_size);
		break;
	case AF_INET6:
		ret = format_sa_inet6((struct sockaddr_in6 *)sa, buf, buf_size);
		break;
	}
	if (ret < 0) {
		ret = snprintf(buf, buf_size, "%s", "???");
	}
	return ret;
}

static bool resolve_inet(
	void *restrict sa, socklen_t *restrict len, const char *hostname,
	const char *service, const int family, const int flags)
{
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | flags,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(hostname, service, &hints, &result);
	if (err != 0) {
		LOGE_F("resolve: %s", gai_strerror(err));
		return NULL;
	}
	for (const struct addrinfo *restrict it = result; it != NULL;
	     it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			continue;
		}
		if (*len < it->ai_addrlen) {
			return false;
		}
		memcpy(sa, it->ai_addr, it->ai_addrlen);
		*len = it->ai_addrlen;
		freeaddrinfo(result);
		return true;
	}
	freeaddrinfo(result);
	return false;
}

bool parse_bindaddr(sockaddr_max_t *sa, const char *s)
{
	const size_t addrlen = strlen(s);
	char buf[FQDN_MAX_LENGTH + 1 + 5 + 1];
	if (addrlen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, s, addrlen);
	buf[addrlen] = '\0';
	char *hoststr = NULL;
	char *portstr = NULL;
	if (!splithostport(buf, &hoststr, &portstr)) {
		return false;
	}
	if (hoststr[0] == '\0') {
		hoststr = "0.0.0.0";
	}
	socklen_t len = sizeof(sockaddr_max_t);
	return resolve_inet(sa, &len, hoststr, portstr, PF_UNSPEC, AI_PASSIVE);
}

bool resolve_hostname(sockaddr_max_t *sa, const char *host, const int family)
{
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(host, NULL, &hints, &result);
	if (err != 0) {
		LOGE_F("resolve: %s", gai_strerror(err));
		return false;
	}
	bool ok = false;
	for (const struct addrinfo *it = result; it; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		ok = true;
		break;
	}
	freeaddrinfo(result);
	return ok;
}
