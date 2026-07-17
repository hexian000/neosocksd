/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "dialer.h"

#include "conf.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "binary/serialize.h"
#include "codec/base64.h"
#include "meta/arraysize.h"
#include "net/addr.h"
#include "net/http.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

const char *const proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

static bool dialaddr_sethostport(
	struct dialaddr *restrict addr, const char *restrict host,
	const uint_fast16_t port)
{
	addr->port = port;
	if (inet_pton(AF_INET, host, &addr->in) == 1) {
		addr->type = ATYP_INET;
		return true;
	}
	if (inet_pton(AF_INET6, host, &addr->in6) == 1) {
		addr->type = ATYP_INET6;
		return true;
	}
	const size_t hostlen = strlen(host);
	if (hostlen > FQDN_MAX_LENGTH) {
		LOGE_F("hostname too long: `%s'", host);
		return false;
	}
	struct domain_name *restrict domain = &addr->domain;
	memcpy(domain->name, host, hostlen);
	domain->len = (uint_least8_t)hostlen;
	addr->type = ATYP_DOMAIN;
	return true;
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	if (len > FQDN_MAX_LENGTH + CONSTSTRLEN(":65535")) {
		LOG_TXT_F(ERROR, s, len, 0, "address too long: %zu bytes", len);
		return false;
	}
	char buf[len + 1];
	memcpy(buf, s, len);
	buf[len] = '\0';

	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		LOGE_F("invalid address: `%s'", s);
		return false;
	}

	char *endptr;
	const uintmax_t portvalue = strtoumax(port, &endptr, 10);
	if (*endptr || portvalue > UINT16_MAX) {
		LOGE_F("unable to parse port number: `%s'", port);
		return false;
	}
	return dialaddr_sethostport(addr, host, (uint_fast16_t)portvalue);
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	switch (sa->sa_family) {
	case AF_INET:
		if ((size_t)len < sizeof(struct sockaddr_in)) {
			return false;
		}
		addr->type = ATYP_INET;
		addr->in = ((struct sockaddr_in *)sa)->sin_addr;
		addr->port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		return true;
	case AF_INET6:
		if ((size_t)len < sizeof(struct sockaddr_in6)) {
			return false;
		}
		addr->type = ATYP_INET6;
		addr->in6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
		addr->port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		return true;
	default:;
	}
	return false;
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	dst->type = src->type;
	dst->port = src->port;
	switch (src->type) {
	case ATYP_INET:
		dst->in = src->in;
		break;
	case ATYP_INET6:
		dst->in6 = src->in6;
		break;
	case ATYP_DOMAIN: {
		const uint_fast8_t len = (uint_fast8_t)src->domain.len;
		dst->domain.len = len;
		memcpy(dst->domain.name, src->domain.name, len);
	} break;
	default:
		FAILMSGF("unexpected address type: %d", src->type);
	}
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	switch (addr->type) {
	case ATYP_INET: {
		char buf[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &addr->in, buf, sizeof(buf)) == NULL) {
			return -1;
		}
		return snprintf(s, maxlen, "%s:%" PRIuLEAST16, buf, addr->port);
	}
	case ATYP_INET6: {
		char buf[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &addr->in6, buf, sizeof(buf)) == NULL) {
			return -1;
		}
		return snprintf(
			s, maxlen, "[%s]:%" PRIuLEAST16, buf, addr->port);
	}
	case ATYP_DOMAIN:
		return snprintf(
			s, maxlen, "%.*s:%" PRIuLEAST16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	FAILMSGF("unexpected address type: %d", addr->type);
}

static const char *dialer_error_strs[DIALER_ERR_MAX] = {
	[DIALER_OK] = "success",
	[DIALER_CANCELLED] = "operation cancelled",
	[DIALER_ERR_SYSTEM] = "system error",
	[DIALER_ERR_RESOLVE] = "name resolution failed",
	[DIALER_ERR_CONNECT] = "connection failed",
	[DIALER_ERR_PROXY_PROTO] = "proxy protocol error",
	[DIALER_ERR_PROXY_AUTH] = "proxy authentication failed",
	[DIALER_ERR_PROXY_REFUSED] = "proxy refused connection",
	[DIALER_ERR_PROXY_REJECT] = "request rejected by proxy",
	[DIALER_ERR_EOF] = "unexpected end of connection",
	[DIALER_ERR_BLOCKED] = "connection blocked by policy",
};

const char *dialer_strerror(const enum dialer_error err)
{
	if (err < DIALER_ERR_MAX && dialer_error_strs[err] != NULL) {
		return dialer_error_strs[err];
	}
	return "unknown error";
}

#define DIALREQ_NEW(n)                                                         \
	(malloc(sizeof(struct dialreq) + sizeof(struct proxyreq) * (n)))

static bool proxy_set_credential(
	struct proxyreq *restrict proxy, const char *restrict username,
	const char *restrict password)
{
	const size_t ulen = (username != NULL) ? strlen(username) + 1 : 0;
	const size_t plen = (password != NULL) ? strlen(password) + 1 : 0;
	if (ulen + plen > sizeof(proxy->credential)) {
		return false;
	}
	if (username != NULL) {
		proxy->username = proxy->credential;
		memcpy(proxy->username, username, ulen);
	} else {
		proxy->username = NULL;
	}
	if (password != NULL) {
		proxy->password = proxy->credential + ulen;
		memcpy(proxy->password, password, plen);
	} else {
		proxy->password = NULL;
	}
	return true;
}

static void
proxy_copy(struct proxyreq *restrict dst, const struct proxyreq *restrict src)
{
	dst->proto = src->proto;
	dialaddr_copy(&dst->addr, &src->addr);
	(void)proxy_set_credential(dst, src->username, src->password);
}

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	const size_t num_base_proxy = (base != NULL) ? base->num_proxy : 0;
	struct dialreq *restrict req = DIALREQ_NEW(num_base_proxy + num_proxy);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	req->num_proxy = num_base_proxy;
	if (base != NULL) {
		dialaddr_copy(&req->addr, &base->addr);
		for (size_t i = 0; i < num_base_proxy; i++) {
			proxy_copy(&req->proxy[i], &base->proxy[i]);
		}
	}
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	/* should be more than enough */
	if (urilen >= 1024) {
		LOGE_F("proxy uri is too long: `%s'", proxy_uri);
		return false;
	}
	char buf[urilen + 1];
	memcpy(buf, proxy_uri, urilen);
	buf[urilen] = '\0';
	struct url uri;
	if (!url_parse(buf, &uri) || uri.scheme == NULL || uri.host == NULL) {
		LOGE_F("unable to parse uri: `%s'", proxy_uri);
		return false;
	}
	enum proxy_protocol protocol;
	char *host, *port;
	if (strcmp(uri.scheme, proxy_protocol_str[PROTO_HTTP]) == 0) {
		protocol = PROTO_HTTP;
		if (!splithostport(uri.host, &host, &port)) {
			host = uri.host;
			port = "80";
		}
	} else if (strcmp(uri.scheme, proxy_protocol_str[PROTO_SOCKS4A]) == 0) {
		protocol = PROTO_SOCKS4A;
		if (!splithostport(uri.host, &host, &port)) {
			host = uri.host;
			port = "1080";
		}
	} else if (strcmp(uri.scheme, proxy_protocol_str[PROTO_SOCKS5]) == 0) {
		protocol = PROTO_SOCKS5;
		if (!splithostport(uri.host, &host, &port)) {
			host = uri.host;
			port = "1080";
		}
	} else {
		LOGE_F("unknown proxy scheme `%s'", uri.scheme);
		return false;
	}
	char *endptr;
	const uintmax_t portvalue = strtoumax(port, &endptr, 10);
	if (*endptr || portvalue > UINT16_MAX) {
		LOGE_F("unable to parse port number: `%s'", port);
		return false;
	}
	struct proxyreq *restrict proxy = &req->proxy[req->num_proxy];
	proxy->proto = protocol;
	if (!dialaddr_sethostport(
		    &proxy->addr, host, (uint_fast16_t)portvalue)) {
		return false;
	}
	proxy->username = NULL;
	proxy->password = NULL;
	if (uri.userinfo != NULL) {
		char *username, *password;
		if (!url_unescape_userinfo(uri.userinfo, &username, &password) ||
		    !proxy_set_credential(proxy, username, password)) {
			LOGE_F("invalid proxy userinfo: `%s'", uri.userinfo);
			return false;
		}
	}
	req->num_proxy++;
	return true;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	size_t len = 0, n = 0;
	if (csv != NULL) {
		len = strlen(csv);
		if (len > 0) {
			n = 1;
		}
		for (size_t i = 0; i < len; i++) {
			if (csv[i] == ',') {
				++n;
			}
		}
	}
	struct dialreq *restrict req = DIALREQ_NEW(n);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	if (addr != NULL) {
		if (!dialaddr_parse(&req->addr, addr, strlen(addr))) {
			dialreq_free(req);
			return NULL;
		}
	} else {
		req->addr = (struct dialaddr){
			.type = ATYP_INET,
			.port = UINT16_C(0),
			.in = { INADDR_ANY },
		};
	}
	req->num_proxy = 0;
	if (n > 0) {
		if (len > UINT16_MAX) {
			LOGE_F("proxy chain too long: %zu bytes", len);
			dialreq_free(req);
			return NULL;
		}
		char buf[len + 1];
		(void)memcpy(buf, csv, len + 1);
		for (const char *tok = strtok(buf, ","); tok != NULL;
		     tok = strtok(NULL, ",")) {
			if (!dialreq_addproxy(req, tok, strlen(tok))) {
				dialreq_free(req);
				return NULL;
			}
		}
	}
	return req;
}

static int format_proxyreq(
	char *restrict s, const size_t maxlen,
	const struct proxyreq *restrict req)
{
	char host[FQDN_MAX_LENGTH + CONSTSTRLEN(":65535")];
	const int nhost = dialaddr_format(host, sizeof(host), &req->addr);
	if (nhost < 0) {
		return nhost;
	}
	const struct url u = {
		/* url_build reads the struct as const; scheme is char * only
		 * because struct url predates const-correctness */
		.scheme = (char *)proxy_protocol_str[req->proto],
		.host = host,
	};
	return url_build(s, maxlen, &u);
}

/* Remaining writable capacity at offset n, snprintf-style: zero when the buffer
 * is absent or already full. */
static size_t
format_avail(const char *restrict s, const int n, const size_t maxlen)
{
	if (s == NULL || (size_t)n >= maxlen) {
		return 0;
	}
	return maxlen - (size_t)n;
}

int dialreq_format(
	char *restrict s, size_t maxlen, const struct dialreq *restrict r)
{
	int n = 0;
	for (size_t i = 0; i < r->num_proxy; i++) {
		{
			const size_t avail = format_avail(s, n, maxlen);
			const int ret = format_proxyreq(
				avail > 0 ? s + n : NULL, avail, &r->proxy[i]);
			if (ret < 0) {
				return ret;
			}
			n += ret;
		}
		{
			const size_t avail = format_avail(s, n, maxlen);
			const int ret =
				snprintf(avail > 0 ? s + n : NULL, avail, "->");
			ASSERT(ret > 0);
			n += ret;
		}
	}
	const size_t avail = format_avail(s, n, maxlen);
	const int ret =
		dialaddr_format(avail > 0 ? s + n : NULL, avail, &r->addr);
	if (ret < 0) {
		return ret;
	}
	n += ret;
	return n;
}

void dialreq_free(struct dialreq *restrict req)
{
	free(req);
}

bool dialreq_replace(
	struct dialreq **restrict req, const char *restrict addr,
	const char *restrict csv)
{
	struct dialreq *restrict newreq = dialreq_parse(addr, csv);
	if (newreq == NULL) {
		return false;
	}
	dialreq_free(*req);
	*req = newreq;
	return true;
}

enum dialer_state {
	/* Initial state, not yet started. */
	STATE_INIT,
	/* Resolving the domain name to an IP address. */
	STATE_RESOLVE,
	/* Establishing the TCP connection. */
	STATE_CONNECT,
	/* First phase of the proxy handshake. */
	STATE_HANDSHAKE1,
	/* Second phase of the proxy handshake. */
	STATE_HANDSHAKE2,
	/* Third phase of the proxy handshake. */
	STATE_HANDSHAKE3,
	/* Connection established or failed. */
	STATE_DONE,
};

static void dialer_stop(struct dialer *restrict d, struct ev_loop *loop)
{
	switch (d->state) {
	case STATE_INIT:
		break;
	case STATE_RESOLVE:
		if (d->resolve_query != NULL) {
			resolve_cancel(d->resolve_query);
			d->resolve_query = NULL;
		}
		/* fallthrough */
	case STATE_CONNECT:
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
	case STATE_HANDSHAKE3:
		ev_io_stop(loop, &d->w_socket);
		break;
	case STATE_DONE:
		break;
	default:;
	}
	ASSERT(!ev_is_active(&d->w_socket) && !ev_is_pending(&d->w_socket));

	/* Close socket if connection wasn't successful */
	if (d->dialed_fd == -1 && d->w_socket.fd != -1) {
		socket_close(d->w_socket.fd);
	}
	d->state = STATE_DONE;
}

static void
finish_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct dialer *restrict d = watcher->data;
	const int fd = d->dialed_fd;
	LOGV_F("dialer [%p]: request finished [fd:%d]", (void *)d->req, fd);
	dialer_stop(d, loop);
	if (fd >= 0 && d->server != NULL) {
		struct server_stats *restrict stats = &d->server->stats;
		const int_fast64_t elapsed =
			clock_monotonic_ns() - (int_fast64_t)d->start_ns;
		stats->connect_ns
			[stats->num_connects % ARRAY_SIZE(stats->connect_ns)] =
			(int_least64_t)elapsed;
		stats->num_connects++;
	}
	d->finish_cb.func(loop, d->finish_cb.data, fd);
}

static int format_status(
	char *restrict s, const size_t maxlen, const struct dialer *restrict d)
{
	const size_t jump = d->jump;
	const struct dialreq *restrict req = d->req;
	ASSERT(jump < req->num_proxy);
	char raddr[FQDN_MAX_LENGTH + CONSTSTRLEN(":65535")], proxy[256];
	const struct dialaddr *restrict addr = &req->addr;
	if (jump + 1 < req->num_proxy) {
		addr = &req->proxy[jump + 1].addr;
	}
	const int nraddr = dialaddr_format(raddr, sizeof(raddr), addr);
	if (nraddr < 0) {
		return nraddr;
	}
	const int nproxy =
		format_proxyreq(proxy, sizeof(proxy), &req->proxy[jump]);
	if (nproxy < 0) {
		return nproxy;
	}
	return snprintf(
		s, maxlen, "connect `%.*s' over [%zu] `%.*s'", nraddr, raddr,
		jump, nproxy, proxy);
}

#define DIALER_LOG_F(level, d, format, ...)                                      \
	do {                                                                     \
		if (!LOGLEVEL(level)) {                                          \
			break;                                                   \
		}                                                                \
		char status_str[256];                                            \
		const int nstatus =                                              \
			format_status(status_str, sizeof(status_str), (d));      \
		if (nstatus < 0) {                                               \
			/* format_status left status_str unwritten; skip       \
			 * rather than feed a negative %.*s precision */ \
			break;                                                   \
		}                                                                \
		LOG_F(level, "%.*s: " format, nstatus, status_str,               \
		      __VA_ARGS__);                                              \
	} while (0)
#define DIALER_LOG(level, d, message) DIALER_LOG_F(level, d, "%s", message)

static bool dialer_send(
	struct dialer *restrict d, const unsigned char *restrict buf,
	const size_t len)
{
	const int fd = d->w_socket.fd;
	LOG_BIN_F(VERYVERBOSE, buf, len, 0, "send: [fd:%d] %zu bytes", fd, len);
	ssize_t nsend;
	do {
		nsend = send(fd, buf, len, 0);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		DIALER_LOG_F(
			DEBUG, d, "send: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}
	if ((size_t)nsend != len) {
		DIALER_LOG_F(
			DEBUG, d, "send: [fd:%d] short send %zu < %zu", fd,
			(size_t)nsend, len);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
	if (d->byt_sent != NULL) {
		*d->byt_sent += (uint_least64_t)nsend;
	}
	return true;
}

#define DIALER_HTTP_REQ_MAXLEN                                                 \
	(CONSTSTRLEN("CONNECT ") + FQDN_MAX_LENGTH +                           \
	 CONSTSTRLEN(":65535 HTTP/1.1\r\n") +                                  \
	 CONSTSTRLEN("Proxy-Authorization: Basic ") + 685 +                    \
	 CONSTSTRLEN("\r\n") + CONSTSTRLEN("\r\n"))

#define HTTP_RSP_MINLEN (CONSTSTRLEN("HTTP/2 200 \r\n\r\n"))

/* RFC 7231: 4.3.6.  CONNECT */
static bool send_http_req(
	struct dialer *restrict d, const struct proxyreq *restrict proxy,
	const struct dialaddr *restrict addr)
{
	char buf[DIALER_HTTP_REQ_MAXLEN];
#define APPEND(b, s)                                                           \
	do {                                                                   \
		if ((b) + CONSTSTRLEN(s) > buf + sizeof(buf)) {                \
			DIALER_LOG(DEBUG, d, "buffer overflow");               \
			d->err = DIALER_ERR_PROXY_PROTO;                       \
			d->syserr = 0;                                         \
			return false;                                          \
		}                                                              \
		memcpy((b), (s), CONSTSTRLEN(s));                              \
		(b) += CONSTSTRLEN(s);                                         \
	} while (0)
	char *b = buf;
	APPEND(b, "CONNECT ");
	const int n = dialaddr_format(b, sizeof(buf) - (b - buf), addr);
	if (n < 0 || (size_t)n >= sizeof(buf) - (b - buf)) {
		DIALER_LOG(DEBUG, d, "failed to format host address");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
	b += n;
	APPEND(b, " HTTP/1.1\r\n");
	if (proxy->username != NULL) {
		APPEND(b, "Proxy-Authorization: Basic ");
		const size_t ulen = strlen(proxy->username);
		const size_t plen =
			(proxy->password != NULL) ? strlen(proxy->password) : 0;
		const size_t srclen = ulen + 1 + plen;
		unsigned char src[srclen];
		memcpy(src, proxy->username, ulen);
		src[ulen] = ':';
		if (plen > 0) {
			memcpy(src + ulen + 1, proxy->password, plen);
		}
		size_t len = sizeof(buf) - (b - buf);
		const bool ok =
			base64_encode((unsigned char *)b, &len, src, srclen);
		if (!ok || b + len > buf + sizeof(buf)) {
			DIALER_LOG(DEBUG, d, "failed to format credential");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return false;
		}
		b += len;
		APPEND(b, "\r\n");
	}
	APPEND(b, "\r\n");
#undef APPEND

	if (!dialer_send(d, (unsigned char *)buf, (size_t)(b - buf))) {
		return false;
	}
	/* SO_RCVLOWAT is a wakeup hint; failure only affects efficiency */
	(void)socket_rcvlowat(d->w_socket.fd, HTTP_RSP_MINLEN);
	return true;
}

static bool send_socks4a_req(
	struct dialer *restrict d, const struct proxyreq *restrict proxy,
	const struct dialaddr *restrict addr)
{
	size_t cap = SOCKS4_HDR_LEN;
	const size_t idlen =
		(proxy->username != NULL) ? strlen(proxy->username) : 0;
	cap += idlen + 1;
	switch (addr->type) {
	case ATYP_INET:
		break;
	case ATYP_INET6:
		cap += INET6_ADDRSTRLEN;
		break;
	case ATYP_DOMAIN:
		cap += addr->domain.len + 1;
		break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
	unsigned char buf[cap];
	struct socks4_hdr h = {
		.version = SOCKS4,
		.command = SOCKS4CMD_CONNECT,
		.port = addr->port,
	};
	unsigned char *userid = buf + SOCKS4_HDR_LEN;
	if (idlen > 0) {
		memcpy(userid, proxy->username, idlen + 1);
	} else {
		userid[0] = '\0';
	}
	size_t len = SOCKS4_HDR_LEN + idlen + 1;
	switch (addr->type) {
	case ATYP_INET:
		h.address = read_uint32(&addr->in);
		break;
	case ATYP_INET6: {
		h.address = UINT32_C(0x000000FF);
		char *restrict b = (char *)buf + len;
		if (inet_ntop(AF_INET6, &addr->in6, b, INET6_ADDRSTRLEN) ==
		    NULL) {
			const int err = errno;
			DIALER_LOG_F(
				DEBUG, d, "inet_ntop: (%d) %s", err,
				strerror(err));
			d->err = DIALER_ERR_SYSTEM;
			d->syserr = err;
			return false;
		}
		len += strlen(b) + 1;
	} break;
	case ATYP_DOMAIN: {
		h.address = UINT32_C(0x000000FF);
		unsigned char *restrict b = buf + len;
		const size_t n = addr->domain.len;
		memcpy(b, addr->domain.name, n);
		b[n] = '\0';
		len += n + 1;
	} break;
	}
	socks4hdr_write(buf, &h);
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	(void)socket_rcvlowat(d->w_socket.fd, SOCKS4_RSP_MINLEN);
	return true;
}

static bool send_socks5_authmethod(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == STATE_HANDSHAKE1);
	if (proxy->username == NULL) {
		const unsigned char buf[] = { SOCKS5, 0x01, SOCKS5AUTH_NOAUTH };
		return dialer_send(d, buf, sizeof(buf));
	}
	const unsigned char buf[] = { SOCKS5, 0x02, SOCKS5AUTH_NOAUTH,
				      SOCKS5AUTH_USERPASS };
	return dialer_send(d, buf, sizeof(buf));
}

static bool send_socks5_auth(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == STATE_HANDSHAKE2);
	ASSERT(proxy->username == proxy->credential);
	const size_t ulen = strlen(proxy->username);
	const size_t plen =
		(proxy->password != NULL) ? strlen(proxy->password) : 0;
	if (ulen > UCHAR_MAX || plen > UCHAR_MAX) {
		DIALER_LOG_F(
			ERROR, d, "socks5 credentials too long: %zu, %zu", ulen,
			plen);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return false;
	}
	const size_t len = 1 + 1 + ulen + 1 + plen;
	unsigned char buf[len];
	unsigned char *restrict p = buf;
	/* version */
	*p++ = 0x01;
	*p++ = (unsigned char)ulen;
	if (ulen > 0) {
		(void)memcpy(p, proxy->username, ulen);
	}
	p += ulen;
	*p++ = (unsigned char)plen;
	if (plen > 0) {
		(void)memcpy(p, proxy->password, plen);
	}
	return dialer_send(d, buf, len);
}

static bool
send_socks5_req(struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	ASSERT(d->state == STATE_HANDSHAKE3);
	size_t cap = SOCKS5_HDR_LEN;
	switch (addr->type) {
	case ATYP_INET:
		cap += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case ATYP_INET6:
		cap += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case ATYP_DOMAIN:
		cap += 1 + addr->domain.len + sizeof(in_port_t);
		break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
	unsigned char buf[cap];
	struct socks5_hdr h = {
		.version = SOCKS5,
		.command = SOCKS5CMD_CONNECT,
		.reserved = 0,
	};
	size_t len = SOCKS5_HDR_LEN;
	switch (addr->type) {
	case ATYP_INET: {
		h.addrtype = SOCKS5ADDR_IPV4;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in, sizeof(addr->in));
		len += sizeof(addr->in);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	case ATYP_INET6: {
		h.addrtype = SOCKS5ADDR_IPV6;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in6, sizeof(addr->in6));
		len += sizeof(addr->in6);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	case ATYP_DOMAIN: {
		h.addrtype = SOCKS5ADDR_DOMAIN;
		unsigned char *restrict lenbuf = buf + len;
		write_uint8(lenbuf, addr->domain.len);
		len += 1;
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->domain.name, addr->domain.len);
		len += addr->domain.len;
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(in_port_t);
	} break;
	}
	socks5hdr_write(buf, &h);
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	(void)socket_rcvlowat(d->w_socket.fd, SOCKS5_RSP_MINLEN);
	return true;
}

static bool send_dispatch(struct dialer *restrict d)
{
	const struct dialreq *restrict req = d->req;
	const size_t jump = d->jump;
	const size_t next = jump + 1;
	const struct proxyreq *restrict proxy = &req->proxy[jump];
	const struct dialaddr *restrict addr =
		next < req->num_proxy ? &req->proxy[next].addr : &req->addr;
	switch (proxy->proto) {
	case PROTO_HTTP:
		return send_http_req(d, proxy, addr);
	case PROTO_SOCKS4A:
		return send_socks4a_req(d, proxy, addr);
	case PROTO_SOCKS5:
		switch (d->state) {
		case STATE_HANDSHAKE1:
			return send_socks5_authmethod(d, proxy);
		case STATE_HANDSHAKE2:
			return send_socks5_auth(d, proxy);
		case STATE_HANDSHAKE3:
			return send_socks5_req(d, addr);
		default:
			break;
		}
		break;
	default:
		break;
	}
	FAILMSGF("unexpected protocol/state: %d/%d", proxy->proto, d->state);
}

static bool consume_rcvbuf(struct dialer *restrict d, const size_t n)
{
	LOGVV_F("recv: consume %zu bytes", n);
	const int fd = d->w_socket.fd;
	const ssize_t nrecv = recv(fd, d->next, n, 0);
	if (nrecv < 0) {
		const int err = errno;
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}
	if ((size_t)nrecv != n) {
		DIALER_LOG_F(DEBUG, d, "recv: [fd:%d] early EOF", fd);
		d->err = DIALER_ERR_EOF;
		d->syserr = 0;
		return false;
	}
	d->next += n;
	if (d->byt_recv != NULL) {
		*d->byt_recv += (uint_least64_t)n;
	}
	return true;
}

static int recv_http_hdr(struct dialer *restrict d)
{
	char *const buf = (char *)d->next;
	char *key, *value;
	char *last = buf, *next;
	for (;;) {
		next = http_parsehdr(last, &key, &value);
		if (next == NULL) {
			DIALER_LOG(DEBUG, d, "http_parsehdr: failed");
			return -1;
		}
		if (next == last) {
			if (!consume_rcvbuf(d, (size_t)(next - buf))) {
				return -1;
			}
			return 1;
		}
		if (key == NULL) {
			break;
		}
		LOGV_F("http: \"%s: %s\"", key, value);
		last = next;
	}

	/* protocol finished */
	if (!consume_rcvbuf(d, (size_t)(next - buf))) {
		return -1;
	}
	return 0;
}

static int recv_http_rsp(struct dialer *restrict d)
{
	ASSERT(d->state == STATE_HANDSHAKE1);
	DIALER_LOG_F(
		DEBUG, d, "state: %d len: %zu cap: %zu", d->state, d->rbuf.len,
		d->rbuf.cap);
	if (d->rbuf.len >= d->rbuf.cap) {
		DIALER_LOG(DEBUG, d, "http: response too long");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	d->rbuf.data[d->rbuf.len] = '\0';
	if (d->next > d->rbuf.data) {
		return recv_http_hdr(d);
	}

	struct http_message msg;
	char *const buf = (char *)d->next;
	char *next = http_parse(buf, &msg);
	if (next == NULL) {
		DIALER_LOG(DEBUG, d, "http_parse: failed");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	if (next == buf) {
		return 1;
	}

	if (strncmp(msg.rsp.version, "HTTP/1.", 7) != 0) {
		DIALER_LOG_F(
			DEBUG, d, "unsupported HTTP version: %s",
			msg.rsp.version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	if (strcmp(msg.rsp.code, "200") != 0) {
		DIALER_LOG_F(
			DEBUG, d, "HTTP: %s %s", msg.rsp.code, msg.rsp.status);
		if (strcmp(msg.rsp.code, "407") == 0) {
			d->err = DIALER_ERR_PROXY_AUTH;
		} else if (strcmp(msg.rsp.code, "403") == 0) {
			d->err = DIALER_ERR_PROXY_REJECT;
		} else if (
			strcmp(msg.rsp.code, "502") == 0 ||
			strcmp(msg.rsp.code, "503") == 0) {
			d->err = DIALER_ERR_PROXY_REFUSED;
		} else {
			d->err = DIALER_ERR_PROXY_PROTO;
		}
		d->syserr = 0;
		return -1;
	}

	if (!consume_rcvbuf(d, (size_t)(next - buf))) {
		return -1;
	}
	return recv_http_hdr(d);
}

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	ASSERT(d->state == STATE_HANDSHAKE1);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	const size_t want = SOCKS4_HDR_LEN;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks4_hdr h;
	socks4hdr_read(&h, hdr);
	const uint_fast8_t version = h.version;
	if (version != UINT8_C(0)) {
		DIALER_LOG_F(
			DEBUG, d,
			"unexpected SOCKS4 response version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t command = h.command;
	switch (command) {
	case SOCKS4RSP_GRANTED:
		break;
	case SOCKS4RSP_REJECTED:
		DIALER_LOG(DEBUG, d, "SOCKS4 request rejected or failed");
		d->err = DIALER_ERR_PROXY_REFUSED;
		d->syserr = 0;
		return -1;
	default:
		DIALER_LOG_F(
			DEBUG, d, "unsupported SOCKS4 command: %" PRIuFAST8,
			command);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	return 0;
}

static const char *socks5_errorstr[] = {
	[SOCKS5RSP_SUCCEEDED] = "Succeeded",
	[SOCKS5RSP_FAIL] = "General SOCKS server failure",
	[SOCKS5RSP_NOALLOWED] = "Connection not allowed by ruleset",
	[SOCKS5RSP_NETUNREACH] = "Network unreachable",
	[SOCKS5RSP_HOSTUNREACH] = "Host unreachable",
	[SOCKS5RSP_CONNREFUSED] = "Connection refused",
	[SOCKS5RSP_TTLEXPIRED] = "TTL expired",
	[SOCKS5RSP_CMDNOSUPPORT] = "Command not supported",
	[SOCKS5RSP_ATYPNOSUPPORT] = "Address type not supported",
};

static int recv_socks5_rsp(struct dialer *restrict d)
{
	ASSERT(d->state == STATE_HANDSHAKE3);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	size_t want = SOCKS5_HDR_LEN;
	if (len < want) {
		return (int)(want - len);
	}

	struct socks5_hdr h;
	socks5hdr_read(&h, hdr);
	const uint_fast8_t version = h.version;
	if (version != SOCKS5) {
		DIALER_LOG_F(
			DEBUG, d,
			"unexpected SOCKS5 response version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t command = h.command;
	if (command != SOCKS5RSP_SUCCEEDED) {
		if (command < ARRAY_SIZE(socks5_errorstr)) {
			DIALER_LOG_F(
				DEBUG, d, "SOCKS5: %s",
				socks5_errorstr[command]);
		} else {
			DIALER_LOG_F(
				DEBUG, d,
				"unsupported SOCKS5 command: %" PRIuFAST8,
				command);
		}
		switch (command) {
		case SOCKS5RSP_NOALLOWED:
			d->err = DIALER_ERR_PROXY_REJECT;
			break;
		case SOCKS5RSP_CONNREFUSED:
			d->err = DIALER_ERR_PROXY_REFUSED;
			break;
		default:
			d->err = DIALER_ERR_PROXY_PROTO;
			break;
		}
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t addrtype = h.addrtype;
	switch (addrtype) {
	case SOCKS5ADDR_IPV4:
		want += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_IPV6:
		want += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_DOMAIN: {
		/* BND.ADDR is [len][domain][port]; the length byte follows the
		 * fixed header, so it must be present before sizing the rest */
		if (len < want + 1) {
			return (int)(want + 1 - len);
		}
		const uint_fast8_t domlen = read_uint8(hdr + want);
		want += 1 + (size_t)domlen + sizeof(in_port_t);
		break;
	}
	default:
		DIALER_LOG_F(
			DEBUG, d, "unexpected SOCKS5 addrtype: %" PRIuFAST8,
			addrtype);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	if (len < want) {
		return (int)(want - len);
	}
	/* protocol finished */
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	return 0;
}

static int recv_socks5_auth(struct dialer *restrict d)
{
	ASSERT(d->state == STATE_HANDSHAKE2);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	const size_t want = 2;
	if (len < want) {
		return (int)(want - len);
	}
	const uint_fast8_t version = read_uint8(hdr + 0);
	const uint_fast8_t status = read_uint8(hdr + 1);
	if (version != 0x01 || status != 0x00) {
		DIALER_LOG_F(
			DEBUG, d,
			"authenticate failed: version=0x%02" PRIxFAST8
			" status=0x%02" PRIxFAST8,
			version, status);
		d->err = DIALER_ERR_PROXY_AUTH;
		d->syserr = 0;
		return -1;
	}
	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	d->state = STATE_HANDSHAKE3;
	if (!send_dispatch(d)) {
		return -1;
	}
	return recv_socks5_rsp(d);
}

static int recv_socks5_authmethod(struct dialer *restrict d)
{
	ASSERT(d->state == STATE_HANDSHAKE1);
	const unsigned char *restrict hdr = d->next;
	const size_t len = (d->rbuf.data + d->rbuf.len) - d->next;
	size_t want = SOCKS5_AUTH_RSP_LEN;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks5_auth_rsp ar;
	socks5authrsp_read(&ar, hdr);
	const uint_fast8_t version = ar.version;
	if (version != SOCKS5) {
		DIALER_LOG_F(
			DEBUG, d, "unsupported SOCKS5 version: %" PRIuFAST8,
			version);
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	const uint_fast8_t method = ar.method;

	if (!consume_rcvbuf(d, want)) {
		return -1;
	}
	switch (method) {
	case SOCKS5AUTH_NOAUTH:
		d->state = STATE_HANDSHAKE3;
		if (!send_dispatch(d)) {
			return -1;
		}
		return recv_socks5_rsp(d);
	case SOCKS5AUTH_USERPASS:
		/* Only NOAUTH is offered when we have no credentials; a server
		 * selecting USERPASS here picked a method we never advertised.
		 * Acting on it would deref a NULL username in send_socks5_auth. */
		if (d->req->proxy[d->jump].username == NULL) {
			DIALER_LOG(
				DEBUG, d,
				"SOCKS5: server selected an auth method that was not offered");
			d->err = DIALER_ERR_PROXY_PROTO;
			d->syserr = 0;
			return -1;
		}
		d->state = STATE_HANDSHAKE2;
		if (!send_dispatch(d)) {
			return -1;
		}
		return recv_socks5_auth(d);
	case SOCKS5AUTH_NOACCEPTABLE:
		DIALER_LOG(DEBUG, d, "SOCKS5 auth: method negotiation failed");
		d->err = DIALER_ERR_PROXY_AUTH;
		d->syserr = 0;
		return -1;
	default:
		break;
	}
	DIALER_LOG_F(
		DEBUG, d,
		"SOCKS5: unexpected auth method %" PRIuFAST8
		" (protocol error?)",
		method);
	d->err = DIALER_ERR_PROXY_PROTO;
	d->syserr = 0;
	return -1;
}

static int
recv_dispatch(struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	switch (proxy->proto) {
	case PROTO_HTTP:
		return recv_http_rsp(d);
	case PROTO_SOCKS4A:
		return recv_socks4a_rsp(d);
	case PROTO_SOCKS5:
		switch (d->state) {
		case STATE_HANDSHAKE1:
			return recv_socks5_authmethod(d);
		case STATE_HANDSHAKE2:
			return recv_socks5_auth(d);
		case STATE_HANDSHAKE3:
			return recv_socks5_rsp(d);
		default:
			break;
		}
		break;
	default:
		break;
	}
	FAILMSGF("unexpected protocol/state: %d/%d", proxy->proto, d->state);
}

static int dialer_recv(struct dialer *restrict d)
{
	const int fd = d->w_socket.fd;
	unsigned char *buf = d->next;
	const size_t n = d->rbuf.cap - d->rbuf.len;
	ssize_t nrecv;
	do {
		nrecv = recv(fd, buf, n, MSG_PEEK);
	} while (nrecv < 0 && errno == EINTR);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 1;
		}
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, err,
			strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return -1;
	}
	if (nrecv == 0) {
		DIALER_LOG_F(DEBUG, d, "recv: [fd:%d] early EOF", fd);
		d->err = DIALER_ERR_EOF;
		d->syserr = 0;
		return -1;
	}
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		if (sockerr == EINTR || sockerr == EAGAIN ||
		    sockerr == EWOULDBLOCK) {
			return 1;
		}
		DIALER_LOG_F(
			DEBUG, d, "recv: [fd:%d] (%d) %s", fd, sockerr,
			strerror(sockerr));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = sockerr;
		return -1;
	}
	/* MSG_PEEK never consumes, so a re-peek before the next
	 * consume_rcvbuf() call re-reads the same bytes already counted in
	 * rbuf.len; recompute the total relative to `buf` (== d->next)
	 * instead of accumulating nrecv onto the previous length. */
	d->rbuf.len = (size_t)(buf - d->rbuf.data) + (size_t)nrecv;
	LOG_BIN_F(
		VERYVERBOSE, buf, (size_t)nrecv, 0, "recv: %zu bytes",
		(size_t)nrecv);

	const int ret = recv_dispatch(d, &d->req->proxy[d->jump]);
	if (ret < 0) {
		return ret;
	}
	if (ret == 0) {
		/* restore default */
		(void)socket_rcvlowat(d->w_socket.fd, 1);
		return 0;
	}
	const size_t want = (d->rbuf.data + d->rbuf.len) - d->next + ret;
	if (want > d->rbuf.cap) {
		DIALER_LOG(DEBUG, d, "recv: header too long");
		d->err = DIALER_ERR_PROXY_PROTO;
		d->syserr = 0;
		return -1;
	}
	(void)socket_rcvlowat(fd, (int)want);
	return 1;
}

/* core of the dialer state machine: connection establishment (EV_WRITE)
 * and proxy handshakes (EV_READ) */
static void socket_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;

	if (revents & EV_WRITE) {
		ASSERT(d->state == STATE_CONNECT);
		const int sockerr = socket_get_error(fd);
		if (sockerr != 0) {
			if (LOGLEVEL(WARNING)) {
				const struct dialreq *restrict req = d->req;
				const struct dialaddr *restrict addr =
					req->num_proxy > 0 ?
						&req->proxy[0].addr :
						&req->addr;
				char addr_str[64];
				dialaddr_format(
					addr_str, sizeof(addr_str), addr);
				LOG_F(WARNING, "connect `%s': (%d) %s",
				      addr_str, sockerr, strerror(sockerr));
			}
			d->err = DIALER_ERR_CONNECT;
			d->syserr = sockerr;
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}

		if (d->req->num_proxy == 0) {
			d->dialed_fd = fd;
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}

		d->state = STATE_HANDSHAKE1;
		if (!send_dispatch(d)) {
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		modify_io_events(loop, watcher, EV_READ);
	}

	if (revents & EV_READ) {
		ASSERT(d->state == STATE_HANDSHAKE1 ||
		       d->state == STATE_HANDSHAKE2 ||
		       d->state == STATE_HANDSHAKE3);
		const int ret = dialer_recv(d);
		if (ret < 0) {
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		if (ret > 0) {
			return;
		}

		/* handshake done, advance to the next hop */
		d->rbuf.len = 0;
		d->next = d->rbuf.data;
		d->jump++;

		if (d->jump >= d->req->num_proxy) {
			d->dialed_fd = fd;
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}

		d->state = STATE_HANDSHAKE1;
		if (!send_dispatch(d)) {
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
	}
}

/* Log a blocked-address message; the caller returns false regardless of the
 * runtime log level (this macro must not carry the control flow itself). */
#define LOG_BLOCKED(level, what, sa)                                           \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char addr_str[64];                                     \
			sa_format(addr_str, sizeof(addr_str), sa);             \
			LOG_F(level, "blocked %s address: %s", what,           \
			      addr_str);                                       \
		}                                                              \
	} while (0)

static bool
check_outbound_sa(struct dialer *restrict d, const struct sockaddr *restrict sa)
{
	/* sa_ipclassify() (vendored, read-only) has no IPv4-mapped awareness,
	 * so a SOCKS5 ATYP_INET6 request for e.g. ::ffff:127.0.0.1 would
	 * otherwise be classified IPCLASS_GLOBAL and bypass block_loopback/
	 * block_local/block_multicast entirely. Classify the embedded IPv4
	 * address instead; keep the original `sa` for logging so blocked
	 * messages still show the real (mapped) address. */
	struct sockaddr_in mapped;
	const struct sockaddr *classify_sa = sa;
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *restrict sa6 =
			(const struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			mapped = (struct sockaddr_in){
				.sin_family = AF_INET,
				.sin_port = sa6->sin6_port,
			};
			memcpy(&mapped.sin_addr, &sa6->sin6_addr.s6_addr[12],
			       sizeof(mapped.sin_addr));
			classify_sa = (const struct sockaddr *)&mapped;
		}
	}
	switch (sa_ipclassify(classify_sa)) {
	case IPCLASS_LOOPBACK:
		if (d->conf->block_loopback) {
			LOG_BLOCKED(DEBUG, "loopback", sa);
			return false;
		}
		break;
	case IPCLASS_MULTICAST:
		if (d->conf->block_multicast) {
			LOG_BLOCKED(DEBUG, "multicast", sa);
			return false;
		}
		break;
	case IPCLASS_LINKLOCAL:
	case IPCLASS_SITELOCAL:
		if (d->conf->block_local) {
			LOG_BLOCKED(DEBUG, "local", sa);
			return false;
		}
		break;
	case IPCLASS_GLOBAL:
		if (d->conf->block_global) {
			LOG_BLOCKED(DEBUG, "non-local", sa);
			return false;
		}
		break;
	default:
		LOG_BLOCKED(ERROR, "invalid", sa);
		return false;
	}
	return true;
}

static bool connect_sa(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct sockaddr *restrict sa)
{
	if (!check_outbound_sa(d, sa)) {
		d->err = DIALER_ERR_BLOCKED;
		d->syserr = 0;
		return false;
	}

	const int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGD_F("socket: (%d) %s", err, strerror(err));
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}

	if (!socket_set_cloexec(fd) || !socket_set_nonblock(fd)) {
		const int err = errno;
		socket_close(fd);
		d->err = DIALER_ERR_SYSTEM;
		d->syserr = err;
		return false;
	}
	const struct config *restrict conf = d->conf;
#if WITH_NETDEVICE
	if (conf->netdev != NULL) {
		socket_bind_netdev(fd, conf->netdev);
	}
#endif
	/* best-effort tuning; failure does not affect correctness */
	(void)socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	(void)socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
#if WITH_TCP_FASTOPEN_CONNECT
	if (conf->tcp_fastopen_connect) {
		/* opportunistic; falls back to a normal handshake on failure */
		(void)socket_set_fastopen_connect(fd, true);
	}
#endif
	if (LOGLEVEL(VERBOSE)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), sa);
		LOG_F(VERBOSE, "connect %s", addr_str);
	}
	d->state = STATE_CONNECT;
	if (connect(fd, sa, sa_len(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			if (LOGLEVEL(WARNING)) {
				char addr_str[64];
				sa_format(addr_str, sizeof(addr_str), sa);
				LOG_F(WARNING, "connect %s: (%d) %s", addr_str,
				      err, strerror(err));
			}
			d->err = DIALER_ERR_CONNECT;
			d->syserr = err;
			socket_close(fd);
			return false;
		}
		ev_io_set(&d->w_socket, fd, EV_WRITE);
		ev_io_start(loop, &d->w_socket);
		return true;
	}

	if (d->req->num_proxy == 0) {
		ev_io_set(&d->w_socket, fd, EV_WRITE);
		ev_io_start(loop, &d->w_socket);
		return true;
	}

	/* install fd on the watcher before dispatching: send_dispatch() sends
	 * the first handshake through d->w_socket.fd; on failure dialer_stop()
	 * closes it (dialed_fd is still -1) */
	d->state = STATE_HANDSHAKE1;
	ev_io_set(&d->w_socket, fd, EV_READ);
	if (!send_dispatch(d)) {
		return false;
	}
	ev_io_start(loop, &d->w_socket);
	return true;
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *ctx,
	const struct sockaddr *restrict sa)
{
	struct dialer *restrict d = ctx;
	ASSERT(q == d->resolve_query);
	(void)q;
	d->resolve_query = NULL;

	const struct dialaddr *restrict dialaddr =
		d->req->num_proxy > 0 ? &d->req->proxy[0].addr : &d->req->addr;
	if (sa == NULL) {
		LOGD_F("name resolution failed: \"%.*s\"",
		       (int)dialaddr->domain.len, dialaddr->domain.name);
		d->err = DIALER_ERR_RESOLVE;
		d->syserr = 0;
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}

	union sockaddr_max addr;
	sa_copy(&addr.sa, sa);
	switch (sa->sa_family) {
	case AF_INET:
		addr.in.sin_port = htons(dialaddr->port);
		break;
	case AF_INET6:
		addr.in6.sin6_port = htons(dialaddr->port);
		break;
	default:
		FAILMSGF("unexpected address family: %d", sa->sa_family);
	}

	if (LOGLEVEL(DEBUG)) {
		char node_str[dialaddr->domain.len + sizeof(":65535")];
		dialaddr_format(node_str, sizeof(node_str), dialaddr);
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), &addr.sa);
		LOG_F(DEBUG, "resolve: `%s' is %s", node_str, addr_str);
	}

	if (!connect_sa(d, loop, &addr.sa)) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
}

/* Reset the per-dial state so a dialer can be re-driven by another dialer_do()
 * without a fresh dialer_init(). The watchers, callback, and byte counters set
 * up once by dialer_init() are left intact. */
static void dialer_reset(struct dialer *restrict d)
{
	d->req = NULL;
	d->resolve_query = NULL;
	d->jump = 0;
	d->state = STATE_INIT;
	d->err = DIALER_OK;
	d->syserr = 0;
	d->w_socket.fd = -1;
	d->dialed_fd = -1;
	d->next = d->rbuf.data;
	BUF_INIT(d->rbuf, 0);
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *const byt_sent, uint_least64_t *const byt_recv)
{
	ev_io_init(&d->w_socket, socket_cb, -1, EV_NONE);
	d->w_socket.data = d;
	ev_init(&d->w_finish, finish_cb);
	d->w_finish.data = d;

	d->finish_cb = *callback;
	d->byt_sent = byt_sent;
	d->byt_recv = byt_recv;
	dialer_reset(d);
}

static void dialer_start(struct dialer *restrict d, struct ev_loop *loop)
{
	const struct dialreq *restrict req = d->req;
	const struct dialaddr *restrict addr =
		req->num_proxy > 0 ? &req->proxy[0].addr : &req->addr;

	switch (addr->type) {
	case ATYP_INET: {
		struct sockaddr_in in = {
			.sin_family = AF_INET,
			.sin_addr = addr->in,
			.sin_port = htons(addr->port),
		};
		if (!connect_sa(d, loop, (struct sockaddr *)&in)) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
	} break;
	case ATYP_INET6: {
		struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET6,
			.sin6_addr = addr->in6,
			.sin6_port = htons(addr->port),
		};
		if (!connect_sa(d, loop, (struct sockaddr *)&in6)) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
	} break;
	case ATYP_DOMAIN: {
		char host[FQDN_MAX_LENGTH + 1];
		memcpy(host, addr->domain.name, addr->domain.len);
		host[addr->domain.len] = '\0';
		d->state = STATE_RESOLVE;
		struct resolve_query *restrict q = resolve_do(
			d->resolver,
			(struct resolve_cb){
				.func = resolve_cb,
				.data = d,
			},
			host, NULL, d->conf->resolve_pf);
		if (q == NULL) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		d->resolve_query = q;
	} break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
}

void dialer_do(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct dialreq *restrict req, const struct config *restrict conf,
	struct resolver *restrict resolver, struct server *restrict server)
{
	if (LOGLEVEL(VERBOSE)) {
		char s[4096];
		int r = dialreq_format(s, sizeof(s), req);
		ASSERT(r > 0);
		LOG_F(VERBOSE, "dialer [%p]: request start, `%.*s'",
		      (void *)req, r, s);
	}

	dialer_reset(d);
	d->req = req;
	d->conf = conf;
	d->resolver = resolver;
	d->start_ns = (int_least64_t)clock_monotonic_ns();
	d->server = server;
	dialer_start(d, loop);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	if (d->state == STATE_DONE) {
		return;
	}
	LOGD_F("dialer [%p]: request cancelled", (void *)d->req);

	d->err = DIALER_CANCELLED;
	d->syserr = 0;
	dialer_stop(d, loop);
	ev_clear_pending(loop, &d->w_finish);
}
