#include "dialer.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/addr.h"
#include "net/url.h"
#include "net/http.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "conf.h"
#include "sockutil.h"
#include "util.h"
#include "resolver.h"

#include <ev.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

bool dialaddr_set(
	struct dialaddr *restrict addr, const char *s, const size_t len)
{
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + 1 + 5) {
		LOG_TXT_F(
			LOG_LEVEL_ERROR, s, len, "address too long: %zu bytes",
			len);
		return false;
	}
	char buf[len + 1];
	memcpy(buf, s, len);
	buf[len] = '\0';
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		LOGE_F("invalid address: \"%s\"", s);
		return false;
	}
	if (sscanf(port, "%" SCNu16, &addr->port) != 1) {
		LOGE_F("unable to parse port number: \"%s\"", port);
		return false;
	}
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
		LOGE_F("hostname too long: \"%s\"", host);
		return false;
	}
	struct domain_name *restrict domain = &addr->domain;
	memcpy(domain->name, host, hostlen);
	domain->len = (uint8_t)hostlen;
	addr->type = ATYP_DOMAIN;
	return true;
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
		dst->domain.len = src->domain.len;
		memcpy(dst->domain.name, src->domain.name, src->domain.len);
		break;
	default:
		FAIL();
	}
}

int dialaddr_format(
	const struct dialaddr *restrict addr, char *buf, const size_t maxlen)
{
	switch (addr->type) {
	case ATYP_INET: {
		char s[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &addr->in, s, sizeof(s)) == NULL) {
			return -1;
		}
		return snprintf(buf, maxlen, "%s:%" PRIu16, s, addr->port);
	}
	case ATYP_INET6: {
		char s[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &addr->in6, s, sizeof(s)) == NULL) {
			return -1;
		}
		return snprintf(buf, maxlen, "[%s]:%" PRIu16, s, addr->port);
	}
	case ATYP_DOMAIN:
		return snprintf(
			buf, maxlen, "%.*s:%" PRIu16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	FAIL();
}

struct dialreq *dialreq_new(const size_t num_proxy)
{
	struct dialreq *restrict req = malloc(
		sizeof(struct dialreq) + sizeof(struct proxy_req) * num_proxy);
	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = num_proxy;
	return req;
}

bool dialreq_setproxy(
	struct dialreq *restrict req, const size_t i, const char *proxy_uri,
	const size_t urilen)
{
	/* should be more than enough */
	if (urilen >= 1024) {
		LOGE_F("proxy uri is too long: \"%s\"", proxy_uri);
		return false;
	}
	char buf[urilen + 1];
	memcpy(buf, proxy_uri, urilen);
	buf[urilen] = '\0';
	struct url uri;
	if (!url_parse(buf, &uri) || uri.scheme == NULL) {
		LOGE_F("unable to parse uri: \"%s\"", proxy_uri);
		return false;
	}
	enum proxy_protocol protocol;
	const char *addr = NULL;
	if (strcmp(uri.scheme, "http") == 0) {
		protocol = PROTO_HTTP;
		addr = uri.host;
	} else if (
		strcmp(uri.scheme, "socks4") == 0 ||
		strcmp(uri.scheme, "socks4a") == 0) {
		protocol = PROTO_SOCKS4A;
		addr = uri.host;
	} else if (strcmp(uri.scheme, "socks5") == 0) {
		protocol = PROTO_SOCKS5;
		addr = uri.host;
	}
	if (addr == NULL) {
		LOGE_F("dialer: invalid proxy \"%s\"", proxy_uri);
		return false;
	}
	struct proxy_req *restrict proxy = &req->proxy[i];
	proxy->proto = protocol;
	const size_t addrlen = strlen(addr);
	if (!dialaddr_set(&proxy->addr, addr, addrlen)) {
		return false;
	}
	return true;
}

struct dialreq *dialreq_parse(const char *csv)
{
	const size_t len = strlen(csv);
	char buf[len + 1];
	memcpy(buf, csv, len + 1);
	size_t n = 0;
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == ',') {
			++n;
		}
	}
	struct dialreq *req = dialreq_new(n);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	bool direct = true;
	for (char *tok = strtok(buf, ","); tok != NULL;
	     tok = strtok(NULL, ",")) {
		if (direct) {
			if (!dialaddr_set(&req->addr, tok, strlen(tok))) {
				dialreq_free(req);
				return NULL;
			}
			direct = false;
			continue;
		}
		if (!dialreq_setproxy(req, --n, tok, strlen(tok))) {
			dialreq_free(req);
			return NULL;
		}
	}
	return req;
}

void dialreq_free(struct dialreq *restrict req)
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
	STATE_DONE,
};

static void
dialer_stop(struct dialer *restrict d, struct ev_loop *loop, const bool ok)
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
	case STATE_HANDSHAKE2: {
		ev_io_stop(loop, &d->w_socket);
	} break;
	case STATE_DONE:
		break;
	}
	if (!ok && d->fd != -1) {
		CLOSE_FD(d->fd);
		d->fd = -1;
	}
	assert(!ev_is_active(&d->w_socket));
	d->state = STATE_DONE;
}

#define DIALER_RETURN(d, loop, ok)                                             \
	do {                                                                   \
		LOGV_F("dialer: [%p] finished ok=%d", (void *)d, (ok));        \
		dialer_stop((d), (loop), (ok));                                \
		(d)->done_cb.cb((loop), (d)->done_cb.ctx);                     \
		return;                                                        \
	} while (0)

static bool
send_req(struct dialer *restrict d, const unsigned char *buf, const size_t len)
{
	LOG_BIN_F(LOG_LEVEL_VERBOSE, buf, len, "send: %zu bytes", len);
	const ssize_t nsend = send(d->fd, buf, len, 0);
	if (nsend < 0) {
		const int err = errno;
		LOGE_F("send: %s", strerror(err));
		d->syserr = err;
		return false;
	} else if ((size_t)nsend != len) {
		LOGE_F("short send: %zu < %zu", (size_t)nsend, len);
		return false;
	}
	return true;
}

/* RFC 7231: 4.3.6.  CONNECT */
static bool
send_http_req(struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	size_t addrlen;
	switch (addr->type) {
	case ATYP_INET:
		addrlen = INET_ADDRSTRLEN;
		break;
	case ATYP_INET6:
		addrlen = INET6_ADDRSTRLEN;
		break;
	case ATYP_DOMAIN:
		addrlen = addr->domain.len + 1 /* '\0' */;
		break;
	default:
		FAIL();
	}

#define STRLEN(s) (sizeof(s) - 1)
#define APPEND(b, s)                                                           \
	do {                                                                   \
		memcpy((b), (s), STRLEN(s));                                   \
		(b) += STRLEN(s);                                              \
	} while (0)
	/* "CONNECT example.org:80 HTTP/1.1\r\n\r\n" */
	size_t cap = STRLEN("CONNECT ") + addrlen +
		     STRLEN(" :65535 HTTP/1.1\r\n\r\n");
	char buf[cap];
	char *b = buf;
	APPEND(b, "CONNECT ");
	const int n = dialaddr_format(addr, b, cap - (size_t)(b - buf));
	if (n <= 0) {
		return false;
	}
	b += n;
	APPEND(b, " HTTP/1.1\r\n\r\n");
#undef APPEND
#undef STRLEN

	return send_req(d, (unsigned char *)buf, (size_t)(b - buf));
}

static bool send_socks4a_req(
	struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	size_t cap = sizeof(struct socks4_hdr) + 1;
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
	unsigned char *const address =
		buf + offsetof(struct socks4_hdr, address);
	buf[sizeof(struct socks4_hdr)] = 0; /* ident = "" */
	size_t len = sizeof(struct socks4_hdr) + 1;
	switch (addr->type) {
	case ATYP_INET:
		memcpy(address, &addr->in, sizeof(addr->in));
		break;
	case ATYP_INET6: {
		write_uint32(address, UINT32_C(0x000000FF));
		char *const b = (char *)buf + len;
		if (inet_ntop(AF_INET6, &addr->in6, b, INET6_ADDRSTRLEN) ==
		    NULL) {
			const int err = errno;
			LOGE_F("inet_ntop: %s", strerror(err));
			return false;
		}
		len += strlen(b) + 1;
	} break;
	case ATYP_DOMAIN: {
		write_uint32(address, UINT32_C(0x000000FF));
		unsigned char *const b = buf + len;
		const size_t n = addr->domain.len;
		memcpy(b, addr->domain.name, n);
		b[n] = '\0';
		len += n + 1;
	} break;
	}
	return send_req(d, buf, len);
}

static bool send_socks5_auth(
	struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	UNUSED(addr);
	unsigned char buf[3] = { SOCKS5, 0x01, 0x00 };
	return send_req(d, buf, sizeof(buf));
}

static bool
send_socks5_req(struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	size_t cap = sizeof(struct socks5_hdr);
	switch (addr->type) {
	case ATYP_INET:
		cap += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case ATYP_INET6:
		cap += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case ATYP_DOMAIN:
		cap += 1 + addr->domain.len;
		break;
	default:
		FAIL();
	}
	unsigned char buf[cap];
	write_uint8(buf + offsetof(struct socks5_hdr, version), SOCKS5);
	write_uint8(
		buf + offsetof(struct socks5_hdr, command), SOCKS5CMD_CONNECT);
	write_uint8(buf + offsetof(struct socks5_hdr, reserved), 0);
	unsigned char *const addrtype =
		buf + offsetof(struct socks5_hdr, addrtype);
	size_t len = sizeof(struct socks5_hdr);
	switch (addr->type) {
	case ATYP_INET: {
		write_uint8(addrtype, SOCKS5ADDR_IPV4);
		unsigned char *const addrbuf = buf + len;
		memcpy(addrbuf, &addr->in, sizeof(addr->in));
		len += sizeof(addr->in);
		unsigned char *const portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	case ATYP_INET6: {
		write_uint8(addrtype, SOCKS5ADDR_IPV6);
		unsigned char *const addrbuf = buf + len;
		memcpy(addrbuf, &addr->in6, sizeof(addr->in6));
		len += sizeof(addr->in6);
		unsigned char *const portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	case ATYP_DOMAIN: {
		write_uint8(addrtype, SOCKS5ADDR_DOMAIN);
		unsigned char *const lenbuf = buf + len;
		write_uint8(lenbuf, addr->domain.len);
		len += sizeof(uint8_t);
		unsigned char *const addrbuf = buf + len;
		memcpy(addrbuf, &addr->domain.name, addr->domain.len);
		len += addr->domain.len;
		unsigned char *const portbuf = buf + len;
		write_uint16(portbuf, addr->port);
		len += sizeof(uint16_t);
	} break;
	}
	return send_req(d, buf, len);
}

static bool send_proxy_req(struct dialer *restrict d)
{
	const struct dialreq *restrict req = d->req;
	const size_t jump = d->jump;
	const size_t next = jump + 1;
	const enum proxy_protocol proto = req->proxy[jump].proto;
	const struct dialaddr *addr =
		next < req->num_proxy ? &req->proxy[next].addr : &req->addr;
	switch (proto) {
	case PROTO_HTTP:
		return send_http_req(d, addr);
	case PROTO_SOCKS4A:
		return send_socks4a_req(d, addr);
	case PROTO_SOCKS5:
		switch (d->state) {
		case STATE_HANDSHAKE1:
			return send_socks5_auth(d, addr);
		case STATE_HANDSHAKE2:
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
	LOGV_F("consume_rcvbuf: %zu bytes", n);
	const ssize_t nrecv = recv(d->fd, d->buf.data, n, 0);
	if (nrecv < 0) {
		const int err = errno;
		LOGE_F("recv: %s", strerror(err));
		return false;
	} else if (nrecv != (ssize_t)n) {
		LOGE_F("recv: short read %zd/%zu", nrecv, n);
		return false;
	}
	return true;
}

static int recv_http_rsp(struct dialer *restrict d)
{
	if (d->buf.len == d->buf.cap) {
		return -1;
	}
	d->buf.data[d->buf.len] = 0;
	struct http_message msg;
	char *buf = (char *)d->buf.data;
	char *next = http_parse(buf, &msg);
	if (next == NULL) {
		LOGE("http_parse: fail");
		return -1;
	} else if (next == buf) {
		return 1;
	}

	if (strncmp(msg.rsp.version, "HTTP/1.", 7) != 0) {
		LOGE_F("http: unsupported protocol %s", msg.rsp.version);
		return -1;
	}
	if (strcmp(msg.rsp.code, "200") != 0) {
		LOGE_F("http: server response %s", msg.rsp.code);
		return -1;
	}

	char *key, *value;
	char *last = next;
	for (;;) {
		next = http_parsehdr(last, &key, &value);
		if (next == NULL) {
			LOGE("http_parsehdr: fail");
		} else if (next == last) {
			return 1;
		}
		if (key == NULL) {
			break;
		}
		LOGV_F("http: \"%s: %s\"", key, value);
		last = next;
	}

	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, (size_t)(next - buf))) {
		return -1;
	}
	return 0;
}

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	if (d->buf.len < sizeof(struct socks4_hdr)) {
		return (int)(sizeof(struct socks4_hdr) - d->buf.len);
	}
	const unsigned char *hdr = d->buf.data;
	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks4_hdr, version));
	if (version != UINT8_C(0)) {
		LOGE_F("unsupported SOCKS version: %" PRIu8, version);
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks4_hdr, command));
	if (command != SOCKS4RSP_GRANTED) {
		LOGE_F("SOCKS4 failure: %" PRIu8, command);
		return -1;
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, sizeof(struct socks4_hdr))) {
		return -1;
	}
	return 0;
}

static int recv_socks5_rsp(struct dialer *restrict d)
{
	assert(d->state == STATE_HANDSHAKE2);
	const unsigned char *hdr = d->buf.data;
	const size_t len = d->buf.len;
	size_t expected = sizeof(struct socks5_hdr);
	if (len < expected) {
		return (int)(expected - len) + 1;
	}

	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks5_hdr, version));
	if (version != SOCKS5) {
		LOGE_F("unsupported SOCKS version: %" PRIu8, version);
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks5_hdr, command));
	if (command != SOCKS5RSP_SUCCEEDED) {
		LOGE_F("SOCKS5 failure: %" PRIu8, command);
		return -1;
	}
	const uint8_t addrtype =
		read_uint8(hdr + offsetof(struct socks5_hdr, addrtype));
	switch (addrtype) {
	case SOCKS5ADDR_IPV4:
		expected += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_IPV6:
		expected += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	default:
		LOGE_F("SOCKS5 invalid addrtype: %" PRIu8, addrtype);
		return -1;
	}
	if (len < expected) {
		return (int)(expected - len);
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, expected)) {
		return -1;
	}
	return 0;
}

static int recv_socks5_auth(struct dialer *restrict d)
{
	assert(d->state == STATE_HANDSHAKE1);
	const size_t rsplen = sizeof(struct socks5_auth_rsp);
	if (d->buf.len < rsplen) {
		return (int)(rsplen - d->buf.len);
	}
	const unsigned char *hdr = d->buf.data;
	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks5_auth_rsp, version));
	if (version != SOCKS5) {
		LOGE_F("unsupported SOCKS version: %" PRIu8, version);
		return -1;
	}
	const uint8_t method =
		read_uint8(hdr + offsetof(struct socks5_auth_rsp, method));
	if (method != SOCKS5AUTH_NOAUTH) {
		LOGE_F("SOCKS5 unsupported auth method: %" PRIu8, method);
		return -1;
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, rsplen)) {
		return -1;
	}
	BUF_CONSUME(d->buf, rsplen);
	d->state = STATE_HANDSHAKE2;
	if (!send_proxy_req(d)) {
		return -1;
	}
	return recv_socks5_rsp(d);
}

static int
recv_dispatch(struct dialer *restrict d, const struct proxy_req *restrict req)
{
	switch (req->proto) {
	case PROTO_HTTP:
		return recv_http_rsp(d);
	case PROTO_SOCKS4A:
		return recv_socks4a_rsp(d);
	case PROTO_SOCKS5:
		switch (d->state) {
		case STATE_HANDSHAKE1:
			return recv_socks5_auth(d);
		case STATE_HANDSHAKE2:
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

static int dialer_recv(
	struct dialer *restrict d, const int fd,
	const struct proxy_req *restrict req)
{
	const ssize_t nrecv = recv(fd, d->buf.data, d->buf.cap, MSG_PEEK);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		LOGE_F("recv: %s", strerror(err));
		d->syserr = err;
		return -1;
	} else if (nrecv == 0) {
		LOGE_F("recv: fd=%d early EOF", fd);
		return -1;
	}
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		if (IS_TRANSIENT_ERROR(sockerr)) {
			return 1;
		}
		LOGE_F("recv: %s", strerror(sockerr));
		return -1;
	}
	d->buf.len = (size_t)nrecv;
	LOG_BIN_F(
		LOG_LEVEL_VERBOSE, d->buf.data, d->buf.len, "recv: %zu bytes",
		d->buf.len);
	const int ret = recv_dispatch(d, req);
	if (ret < 0) {
		return ret;
	} else if (ret == 0) {
		socket_rcvlowat(d->fd, 1);
		return 0;
	}
	const size_t want = d->buf.len + (size_t)ret;
	if (want > d->buf.cap) {
		LOGE("recv: header too long");
		return -1;
	}
	socket_rcvlowat(fd, want);
	return 1;
}

static int on_connected(struct dialer *restrict d, const int fd)
{
	assert(d->state == STATE_CONNECT);
	const struct dialreq *restrict req = d->req;
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		LOGE_F("connect: %s", strerror(sockerr));
		d->syserr = sockerr;
		return -1;
	}

	if (d->jump >= req->num_proxy) {
		return 0;
	}

	d->state = STATE_HANDSHAKE1;
	if (!send_proxy_req(d)) {
		return -1;
	}
	return 1;
}

static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;
	if (revents & EV_WRITE) {
		ev_io_stop(loop, watcher);
		const int ret = on_connected(d, fd);
		if (ret < 0) {
			DIALER_RETURN(d, loop, false);
		} else if (ret == 0) {
			DIALER_RETURN(d, loop, true);
		}
		ev_io_set(watcher, fd, EV_READ);
		ev_io_start(loop, watcher);
		return;
	}

	assert(d->state == STATE_HANDSHAKE1 || d->state == STATE_HANDSHAKE2);
	const int ret = dialer_recv(d, fd, &d->req->proxy[d->jump]);
	if (ret < 0) {
		DIALER_RETURN(d, loop, false);
	} else if (ret > 0) {
		/* want more data */
		return;
	}

	d->buf.len = 0;
	d->jump++;
	if (d->jump >= d->req->num_proxy) {
		DIALER_RETURN(d, loop, true);
	}

	d->state = STATE_HANDSHAKE1;
	if (!send_proxy_req(d)) {
		DIALER_RETURN(d, loop, false);
	}
}

static bool connect_sa(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct sockaddr *sa)
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
	if (connect(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			LOGE_F("connect: %s", strerror(err));
			CLOSE_FD(fd);
			d->syserr = err;
			return false;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "dialer: CONNECT \"%s\"", addr_str);
	}
	d->fd = fd;

	struct ev_io *restrict w_socket = &d->w_socket;
	ev_io_set(w_socket, fd, EV_WRITE);
	ev_io_start(loop, w_socket);

	d->state = STATE_CONNECT;
	return true;
}

static void resolve_cb(struct ev_loop *loop, void *data)
{
	struct dialer *restrict d = data;
	const struct dialaddr *restrict dialaddr =
		d->req->num_proxy > 0 ? &d->req->proxy[0].addr : &d->req->addr;

	sockaddr_max_t addr;
	if (!resolve_get(&addr, d->resolve_query)) {
		LOGE_F("name resolution failed: \"%.*s\"",
		       (int)dialaddr->domain.len, dialaddr->domain.name);
		return;
	}

	switch (addr.sa.sa_family) {
	case AF_INET:
		addr.in.sin_port = htons(dialaddr->port);
		break;
	case AF_INET6:
		addr.in6.sin6_port = htons(dialaddr->port);
		break;
	default:
		FAIL();
	}

	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char node_str[dialaddr->domain.len + 1 + 5 + 1];
		dialaddr_format(dialaddr, node_str, sizeof(node_str));
		char addr_str[64];
		format_sa(&addr.sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "resolve: \"%s\" is %s", node_str,
		      addr_str);
	}

	if (!connect_sa(d, loop, &addr.sa)) {
		DIALER_RETURN(d, loop, false);
	}
}

void dialer_init(struct dialer *restrict d, const struct event_cb cb)
{
	d->done_cb = cb;
	d->req = NULL;
	d->resolve_query = NULL;
	d->jump = 0;
	d->state = STATE_INIT;
	d->fd = -1;
	d->syserr = 0;
	{
		struct ev_io *restrict w_socket = &d->w_socket;
		ev_io_init(w_socket, socket_cb, -1, EV_NONE);
		w_socket->data = d;
	}
	BUF_INIT(d->buf, 0);
}

void dialer_start(
	struct dialer *restrict d, struct ev_loop *restrict loop,
	const struct dialreq *restrict req)
{
	LOGV_F("dialer: [%p] start", (void *)d);
	d->req = req;
	d->syserr = 0;
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
			DIALER_RETURN(d, loop, false);
		}
	} break;
	case ATYP_INET6: {
		struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET,
			.sin6_addr = addr->in6,
			.sin6_port = htons(addr->port),
		};
		if (!connect_sa(d, loop, (struct sockaddr *)&in6)) {
			DIALER_RETURN(d, loop, false);
		}
	} break;
	case ATYP_DOMAIN: {
		char host[FQDN_MAX_LENGTH + 1];
		memcpy(host, addr->domain.name, addr->domain.len);
		host[addr->domain.len] = '\0';
		d->state = STATE_RESOLVE;
		struct resolve_query *q = resolve_new(
			G.resolver, (struct event_cb){
					    .cb = resolve_cb,
					    .ctx = d,
				    });
		if (q == NULL) {
			DIALER_RETURN(d, loop, false);
		}
		d->resolve_query = q;
		resolve_start(q, host, NULL, G.conf->resolve_pf);
	} break;
	default:
		FAIL();
	}
}

int dialer_get(struct dialer *d)
{
	assert(d->state == STATE_DONE);
	return d->fd;
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *loop)
{
	LOGV_F("dialer: [%p] cancel", (void *)d);
	dialer_stop(d, loop, false);
}
