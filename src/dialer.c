/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "dialer.h"

#include "conf.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "resolver.h"
#include "sockutil.h"
#include "util.h"

#include "codec/base64.h"
#include "net/addr.h"
#include "net/http.h"
#include "net/url.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
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

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

static bool dialaddr_set(
	struct dialaddr *restrict addr, const char *restrict host,
	const uint16_t port)
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
	domain->len = (uint8_t)hostlen;
	addr->type = ATYP_DOMAIN;
	return true;
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + 1 + 5) {
		LOG_TXT_F(ERROR, s, len, "address too long: %zu bytes", len);
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
	return dialaddr_set(addr, host, (uint16_t)portvalue);
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
	case ATYP_DOMAIN:
		memcpy(dst->domain.name, src->domain.name,
		       dst->domain.len = src->domain.len);
		break;
	default:
		FAIL();
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
		return snprintf(s, maxlen, "%s:%" PRIu16, buf, addr->port);
	}
	case ATYP_INET6: {
		char buf[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &addr->in6, buf, sizeof(buf)) == NULL) {
			return -1;
		}
		return snprintf(s, maxlen, "[%s]:%" PRIu16, buf, addr->port);
	}
	case ATYP_DOMAIN:
		return snprintf(
			s, maxlen, "%.*s:%" PRIu16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	FAIL();
}

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
	}
	if (password != NULL) {
		proxy->password = proxy->credential + ulen;
		memcpy(proxy->password, password, plen);
	}
	return true;
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
		LOGE_F("dialer: unknown proxy scheme `%s'", uri.scheme);
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
	if (!dialaddr_set(&proxy->addr, host, (uint16_t)portvalue)) {
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

#define DIALREQ_NEW(n)                                                         \
	(malloc(sizeof(struct dialreq) + sizeof(struct proxyreq) * (n)))

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
		char buf[len + 1];
		(void)memcpy(buf, csv, len + 1);
		for (char *tok = strtok(buf, ","); tok != NULL;
		     tok = strtok(NULL, ",")) {
			if (!dialreq_addproxy(req, tok, strlen(tok))) {
				dialreq_free(req);
				return NULL;
			}
		}
	}
	return req;
}

static void
proxy_copy(struct proxyreq *restrict dst, const struct proxyreq *restrict src)
{
	dst->proto = src->proto;
	dialaddr_copy(&dst->addr, &src->addr);
	(void)proxy_set_credential(dst, src->username, src->password);
}

static int format_proxyreq(
	char *restrict s, size_t maxlen, const struct proxyreq *restrict req)
{
	char host[FQDN_MAX_LENGTH + 1 + 5];
	int nhost = dialaddr_format(host, sizeof(host), &req->addr);
	ASSERT(nhost > 0);
	if (maxlen < (size_t)(nhost + 1)) {
		return -1;
	}
	const struct url u = {
		.scheme = (char *)proxy_protocol_str[req->proto],
		.host = host,
	};
	const size_t n = url_build(s, maxlen - 1, &u);
	s[n] = '\0';
	return (int)n;
}

int dialreq_format(
	char *restrict s, size_t maxlen, const struct dialreq *restrict r)
{
	if (maxlen == 0) {
		return 0;
	}
	if (maxlen > INT_MAX) {
		maxlen = INT_MAX;
	}
	int n = 0;
	for (size_t i = 0; i < r->num_proxy; i++) {
		int ret = format_proxyreq(s, maxlen, &r->proxy[i]);
		s += ret;
		maxlen -= ret;
		n += ret;
		ret = snprintf(s, maxlen, "->");
		ASSERT(ret > 0);
		s += ret;
		maxlen -= ret;
		n += ret;
		if (maxlen <= 1) {
			return n;
		}
	}
	int ret = dialaddr_format(s, maxlen, &r->addr);
	ASSERT(ret > 0);
	n += ret;
	return n;
}

struct dialreq *dialreq_new(const size_t num_proxy)
{
	struct dialreq *restrict base = G.basereq;
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

void dialreq_free(struct dialreq *req)
{
	free(req);
}

/* never rollback */
enum dialer_state {
	STATE_INIT,
	STATE_RESOLVE,
	STATE_CONNECT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_HANDSHAKE3,
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
	}
	ASSERT(!ev_is_active(&d->w_socket) && !ev_is_pending(&d->w_socket));
	if (d->socket_fd == -1 && d->w_socket.fd != -1) {
		CLOSE_FD(d->w_socket.fd);
	}
	d->state = STATE_DONE;
}

static void
finish_cb(struct ev_loop *loop, struct ev_watcher *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct dialer *restrict d = watcher->data;
	const int fd = d->socket_fd;
	LOGV_F("dialer %p: finished fd=%d", (void *)d, fd);
	dialer_stop(d, loop);
	d->finish_cb.func(loop, d->finish_cb.data, fd);
}

static int
format_status(char *restrict s, size_t maxlen, const struct dialer *restrict d)
{
	const size_t jump = d->jump;
	const struct dialreq *restrict req = d->req;
	ASSERT(jump < req->num_proxy);
	char raddr[64], proxy[256];
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

#define DIALER_LOG_F(level, d, format, ...)                                    \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char status_str[256];                                          \
		const int nstatus =                                            \
			format_status(status_str, sizeof(status_str), (d));    \
		ASSERT(nstatus > 0);                                           \
		LOG_F(level, "%.*s: " format, nstatus, status_str,             \
		      __VA_ARGS__);                                            \
	} while (0)
#define DIALER_LOG(level, d, message) DIALER_LOG_F(level, d, "%s", message)

static bool dialer_send(
	struct dialer *restrict d, const unsigned char *restrict buf,
	const size_t len)
{
	const int fd = d->w_socket.fd;
	LOG_BIN_F(VERYVERBOSE, buf, len, "send: fd=%d %zu bytes", fd, len);
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		const int err = errno;
		DIALER_LOG_F(WARNING, d, "send: fd=%d %s", fd, strerror(err));
		d->syserr = err;
		return false;
	}
	if ((size_t)nsend != len) {
		DIALER_LOG_F(
			WARNING, d, "send: fd=%d short send %zu < %zu", fd,
			(size_t)nsend, len);
		return false;
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
		if (b + CONSTSTRLEN(s) > buf + sizeof(buf)) {                  \
			DIALER_LOG(ERROR, d, "buffer overflow");               \
			return false;                                          \
		}                                                              \
		memcpy((b), (s), CONSTSTRLEN(s));                              \
		(b) += CONSTSTRLEN(s);                                         \
	} while (0)
	char *b = buf;
	APPEND(b, "CONNECT ");
	const int n = dialaddr_format(b, sizeof(buf) - (b - buf), addr);
	if (n < 0 || (size_t)n >= sizeof(buf) - (b - buf)) {
		DIALER_LOG(ERROR, d, "failed to format host address");
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
			DIALER_LOG(ERROR, d, "failed to format credential");
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
	socket_rcvlowat(d->w_socket.fd, HTTP_RSP_MINLEN);
	return true;
}

static bool send_socks4a_req(
	struct dialer *restrict d, const struct proxyreq *restrict proxy,
	const struct dialaddr *restrict addr)
{
	size_t cap = sizeof(struct socks4_hdr);
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
		FAIL();
	}
	unsigned char buf[cap];
	write_uint8(buf + offsetof(struct socks4_hdr, version), SOCKS4);
	write_uint8(
		buf + offsetof(struct socks4_hdr, command), SOCKS4CMD_CONNECT);
	write_uint16(buf + offsetof(struct socks4_hdr, port), addr->port);
	unsigned char *address = buf + offsetof(struct socks4_hdr, address);
	unsigned char *userid = buf + sizeof(struct socks4_hdr);
	if (idlen > 0) {
		memcpy(userid, proxy->username, idlen + 1);
	} else {
		userid[0] = '\0';
	}
	size_t len = sizeof(struct socks4_hdr) + idlen + 1;
	switch (addr->type) {
	case ATYP_INET:
		memcpy(address, &addr->in, sizeof(addr->in));
		break;
	case ATYP_INET6: {
		write_uint32(address, UINT32_C(0x000000FF));
		char *restrict b = (char *)buf + len;
		if (inet_ntop(AF_INET6, &addr->in6, b, INET6_ADDRSTRLEN) ==
		    NULL) {
			LOGE_F("inet_ntop: %s", strerror(errno));
			return false;
		}
		len += strlen(b) + 1;
	} break;
	case ATYP_DOMAIN: {
		write_uint32(address, UINT32_C(0x000000FF));
		unsigned char *restrict b = buf + len;
		const size_t n = addr->domain.len;
		memcpy(b, addr->domain.name, n);
		b[n] = '\0';
		len += n + 1;
	} break;
	}
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	socket_rcvlowat(d->w_socket.fd, SOCKS4_RSP_MINLEN);
	return true;
}

static bool send_socks5_authmethod(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == STATE_HANDSHAKE1);
	if (proxy->username == NULL) {
		unsigned char buf[] = { SOCKS5, 0x01, SOCKS5AUTH_NOAUTH };
		return dialer_send(d, buf, sizeof(buf));
	}
	unsigned char buf[] = { SOCKS5, 0x02, SOCKS5AUTH_NOAUTH,
				SOCKS5AUTH_USERPASS };
	return dialer_send(d, buf, sizeof(buf));
}

static bool send_socks5_auth(
	struct dialer *restrict d, const struct proxyreq *restrict proxy)
{
	ASSERT(d->state == STATE_HANDSHAKE2);
	const size_t ulen = strlen(proxy->username);
	const size_t plen =
		(proxy->password != NULL) ? strlen(proxy->password) : 0;
	if (ulen > UCHAR_MAX || plen > UCHAR_MAX) {
		DIALER_LOG_F(
			ERROR, d, "socks5 credentials too long: %zu, %zu", ulen,
			plen);
		return false;
	}
	const size_t len = 1 + 1 + ulen + 1 + plen;
	unsigned char buf[len];
	unsigned char *restrict p = buf;
	*p++ = 0x01; /* version */
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
	size_t cap = sizeof(struct socks5_hdr);
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
		FAIL();
	}
	unsigned char buf[cap];
	write_uint8(buf + offsetof(struct socks5_hdr, version), SOCKS5);
	write_uint8(
		buf + offsetof(struct socks5_hdr, command), SOCKS5CMD_CONNECT);
	write_uint8(buf + offsetof(struct socks5_hdr, reserved), 0);
	unsigned char *restrict addrtype =
		buf + offsetof(struct socks5_hdr, addrtype);
	size_t len = sizeof(struct socks5_hdr);
	switch (addr->type) {
	case ATYP_INET: {
		write_uint8(addrtype, SOCKS5ADDR_IPV4);
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in, sizeof(addr->in));
		len += sizeof(addr->in);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	case ATYP_INET6: {
		write_uint8(addrtype, SOCKS5ADDR_IPV6);
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->in6, sizeof(addr->in6));
		len += sizeof(addr->in6);
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	case ATYP_DOMAIN: {
		write_uint8(addrtype, SOCKS5ADDR_DOMAIN);
		unsigned char *restrict lenbuf = buf + len;
		write_uint8(lenbuf, addr->domain.len);
		len += sizeof(uint8_t);
		unsigned char *restrict addrbuf = buf + len;
		memcpy(addrbuf, &addr->domain.name, addr->domain.len);
		len += addr->domain.len;
		unsigned char *restrict portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	}
	if (!dialer_send(d, buf, len)) {
		return false;
	}
	socket_rcvlowat(d->w_socket.fd, SOCKS5_RSP_MINLEN);
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
	FAIL();
}

static bool consume_rcvbuf(struct dialer *restrict d, const size_t n)
{
	LOGVV_F("recv: consume %zu bytes", n);
	const int fd = d->w_socket.fd;
	const ssize_t nrecv = recv(fd, d->next, n, 0);
	if (nrecv < 0) {
		const int err = errno;
		DIALER_LOG_F(WARNING, d, "recv: fd=%d %s", fd, strerror(err));
		return false;
	}
	if ((size_t)nrecv != n) {
		DIALER_LOG_F(WARNING, d, "recv: fd=%d early EOF", fd);
		return false;
	}
	d->next += n;
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
			DIALER_LOG(ERROR, d, "http_parsehdr: failed");
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
		DIALER_LOG(ERROR, d, "http: response too long");
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
		DIALER_LOG(ERROR, d, "http_parse: failed");
		return -1;
	}
	if (next == buf) {
		return 1;
	}

	if (strncmp(msg.rsp.version, "HTTP/1.", 7) != 0) {
		DIALER_LOG_F(
			ERROR, d, "unsupported HTTP version: %s",
			msg.rsp.version);
		return -1;
	}
	if (strcmp(msg.rsp.code, "200") != 0) {
		DIALER_LOG_F(
			ERROR, d, "HTTP: %s %s", msg.rsp.code, msg.rsp.status);
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
	const size_t want = sizeof(struct socks4_hdr);
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks4_hdr, version));
	if (version != UINT8_C(0)) {
		DIALER_LOG_F(
			ERROR, d, "unexpected SOCKS4 response version: %" PRIu8,
			version);
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks4_hdr, command));
	switch (command) {
	case SOCKS4RSP_GRANTED:
		break;
	case SOCKS4RSP_REJECTED:
		DIALER_LOG(ERROR, d, "SOCKS4 request rejected or failed");
		return -1;
	default:
		DIALER_LOG_F(
			ERROR, d, "unsupported SOCKS4 command: %" PRIu8,
			command);
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
	size_t want = sizeof(struct socks5_hdr);
	if (len < want) {
		return (int)(want - len) + 1;
	}

	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks5_hdr, version));
	if (version != SOCKS5) {
		DIALER_LOG_F(
			ERROR, d, "unexpected SOCKS5 response version: %" PRIu8,
			version);
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks5_hdr, command));
	if (command != SOCKS5RSP_SUCCEEDED) {
		if (command < ARRAY_SIZE(socks5_errorstr)) {
			DIALER_LOG_F(
				ERROR, d, "SOCKS5: %s",
				socks5_errorstr[command]);
			return -1;
		}
		DIALER_LOG_F(
			ERROR, d, "unsupported SOCKS5 command: %" PRIu8,
			command);
		return -1;
	}
	const uint8_t addrtype =
		read_uint8(hdr + offsetof(struct socks5_hdr, addrtype));
	switch (addrtype) {
	case SOCKS5ADDR_IPV4:
		want += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_IPV6:
		want += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	default:
		DIALER_LOG_F(
			ERROR, d, "unexpected SOCKS5 addrtype: %" PRIu8,
			addrtype);
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
	const uint8_t version = read_uint8(hdr + 0);
	const uint8_t status = read_uint8(hdr + 1);
	if (version != 0x01 || status != 0x00) {
		DIALER_LOG_F(
			ERROR, d,
			"authenticate failed: version=0x%02" PRIx8
			" status=0x%02" PRIx8,
			version, status);
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
	size_t want = sizeof(struct socks5_auth_rsp);
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks5_auth_rsp, version));
	if (version != SOCKS5) {
		DIALER_LOG_F(
			ERROR, d, "unsupported SOCKS5 version: %" PRIu8,
			version);
		return -1;
	}
	const uint8_t method =
		read_uint8(hdr + offsetof(struct socks5_auth_rsp, method));

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
		d->state = STATE_HANDSHAKE2;
		if (!send_dispatch(d)) {
			return -1;
		}
		return recv_socks5_auth(d);
	default:
		break;
	}
	DIALER_LOG_F(
		ERROR, d, "unsupported SOCKS5 auth method: %" PRIu8, method);
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
	FAIL();
}

static int dialer_recv(struct dialer *restrict d)
{
	const int fd = d->w_socket.fd;
	unsigned char *buf = d->next;
	const size_t n = d->rbuf.cap - d->rbuf.len;
	const ssize_t nrecv = recv(fd, buf, n, MSG_PEEK);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		DIALER_LOG_F(WARNING, d, "recv: fd=%d %s", fd, strerror(err));
		d->syserr = err;
		return -1;
	}
	if (nrecv == 0) {
		DIALER_LOG_F(WARNING, d, "recv: fd=%d early EOF", fd);
		return -1;
	}
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		if (IS_TRANSIENT_ERROR(sockerr)) {
			return 1;
		}
		DIALER_LOG_F(
			WARNING, d, "recv: fd=%d %s", fd, strerror(sockerr));
		return -1;
	}
	d->rbuf.len += (size_t)nrecv;
	LOG_BIN_F(
		VERYVERBOSE, buf, (size_t)nrecv, "recv: %zu bytes",
		(size_t)nrecv);

	const int ret = recv_dispatch(d, &d->req->proxy[d->jump]);
	if (ret < 0) {
		return ret;
	}
	if (ret == 0) {
		/* restore default */
		socket_rcvlowat(d->w_socket.fd, 1);
		return 0;
	}
	const size_t want = (d->rbuf.data + d->rbuf.len) - d->next + ret;
	if (want > d->rbuf.cap) {
		DIALER_LOG(ERROR, d, "recv: header too long");
		return -1;
	}
	socket_rcvlowat(fd, want);
	return 1;
}

static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
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
				LOG_F(WARNING, "connect `%s': %s", addr_str,
				      strerror(sockerr));
			}
			d->syserr = sockerr;
			ev_invoke(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		if (d->req->num_proxy == 0) {
			d->socket_fd = fd;
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
			/* want more data */
			return;
		}

		/* clear buffer for next jump */
		d->rbuf.len = 0;
		d->next = d->rbuf.data;
		d->jump++;
		if (d->jump >= d->req->num_proxy) {
			d->socket_fd = fd;
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

static bool connect_sa(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct sockaddr *restrict sa)
{
	const int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		d->syserr = err;
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		CLOSE_FD(fd);
		d->syserr = err;
		return false;
	}
	const struct config *restrict conf = G.conf;
#if WITH_NETDEVICE
	if (conf->netdev != NULL) {
		socket_bind_netdev(fd, conf->netdev);
	}
#endif
	socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
#if WITH_TCP_FASTOPEN_CONNECT
	if (conf->tcp_fastopen_connect) {
		socket_set_fastopen_connect(fd, true);
	}
#endif
	ev_io_set(&d->w_socket, fd, EV_NONE);
	if (LOGLEVEL(VERBOSE)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), sa);
		LOG_F(VERBOSE, "dialer: connect %s", addr_str);
	}
	d->state = STATE_CONNECT;
	if (connect(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			if (LOGLEVEL(WARNING)) {
				char addr_str[64];
				format_sa(addr_str, sizeof(addr_str), sa);
				LOG_F(WARNING, "connect %s: %s", addr_str,
				      strerror(err));
			}
			d->syserr = err;
			CLOSE_FD(fd);
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

	d->state = STATE_HANDSHAKE1;
	if (!send_dispatch(d)) {
		CLOSE_FD(fd);
		return false;
	}
	ev_io_set(&d->w_socket, fd, EV_READ);
	ev_io_start(loop, &d->w_socket);
	return true;
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *ctx,
	const struct sockaddr *restrict sa)
{
	struct dialer *restrict d = ctx;
	ASSERT(q == d->resolve_query);
	UNUSED(q);
	d->resolve_query = NULL;

	const struct dialaddr *restrict dialaddr =
		d->req->num_proxy > 0 ? &d->req->proxy[0].addr : &d->req->addr;
	if (sa == NULL) {
		LOGW_F("name resolution failed: \"%.*s\"",
		       (int)dialaddr->domain.len, dialaddr->domain.name);
		return;
	}

	union sockaddr_max addr;
	copy_sa(&addr.sa, sa);
	switch (sa->sa_family) {
	case AF_INET:
		addr.in.sin_port = htons(dialaddr->port);
		break;
	case AF_INET6:
		addr.in6.sin6_port = htons(dialaddr->port);
		break;
	default:
		FAIL();
	}

	if (LOGLEVEL(DEBUG)) {
		char node_str[dialaddr->domain.len + 1 + 5 + 1];
		dialaddr_format(node_str, sizeof(node_str), dialaddr);
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), &addr.sa);
		LOG_F(DEBUG, "resolve: `%s' is %s", node_str, addr_str);
	}

	if (!connect_sa(d, loop, &addr.sa)) {
		ev_invoke(loop, &d->w_finish, EV_CUSTOM);
		return;
	}
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
			.sin6_family = AF_INET,
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
			G.resolver,
			(struct resolve_cb){
				.func = resolve_cb,
				.data = d,
			},
			host, NULL, G.conf->resolve_pf);
		if (q == NULL) {
			ev_feed_event(loop, &d->w_finish, EV_CUSTOM);
			return;
		}
		d->resolve_query = q;
	} break;
	default:
		FAIL();
	}
}

void dialer_init(struct dialer *restrict d, const struct dialer_cb *callback)
{
	d->req = NULL;
	d->resolve_query = NULL;
	d->jump = 0;
	d->state = STATE_INIT;
	d->syserr = 0;
	ev_io_init(&d->w_socket, socket_cb, -1, EV_NONE);
	d->w_socket.data = d;
	d->socket_fd = -1;
	ev_init(&d->w_finish, finish_cb);
	d->w_finish.data = d;
	d->finish_cb = *callback;
	d->next = d->rbuf.data;
	BUF_INIT(d->rbuf, 0);
}

void dialer_do(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct dialreq *restrict req)
{
	if (LOGLEVEL(VERBOSE)) {
		char s[4096];
		int r = dialreq_format(s, sizeof(s), req);
		ASSERT(r > 0);
		LOG_F(VERBOSE, "dialer %p: start, `%.*s'", (void *)d, r, s);
	}
	d->req = req;
	d->syserr = 0;
	dialer_start(d, loop);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *loop)
{
	LOGV_F("dialer %p: cancel", (void *)d);
	ev_clear_pending(loop, &d->w_finish);
	dialer_stop(d, loop);
}
