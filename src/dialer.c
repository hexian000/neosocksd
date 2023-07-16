#include "dialer.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/addr.h"
#include "net/url.h"
#include "proto/socks.h"
#include "conf.h"
#include "sockutil.h"
#include "util.h"

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

bool dialaddr_set(struct dialaddr *restrict addr, const char *s, size_t len)
{
	char buf[FQDN_MAX_LENGTH + 1 + 5 + 1]; /* FQDN + ':' + port + '\0' */
	if (len >= sizeof(buf)) {
		LOGE_F("address too long: \"%s\"", s);
		return false;
	}
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

int dialaddr_format(
	const struct dialaddr *restrict addr, char *buf, size_t bufsize)
{
	if (addr->type == ATYP_DOMAIN) {
		return snprintf(
			buf, bufsize, "%.*s:%" PRIu16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	}

	switch (addr->type) {
	case ATYP_INET: {
		const struct sockaddr_in in = {
			.sin_family = AF_INET,
			.sin_addr = addr->in,
			.sin_port = htons(addr->port),
		};
		return format_sa((const struct sockaddr *)&in, buf, bufsize);
	}
	case ATYP_INET6: {
		const struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET6,
			.sin6_addr = addr->in6,
			.sin6_port = htons(addr->port),
		};
		return format_sa((const struct sockaddr *)&in6, buf, bufsize);
	}
	case ATYP_DOMAIN:
		return snprintf(
			buf, bufsize, "%.*s%" PRIu16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	FAIL();
}

struct dialreq *
dialreq_new(const struct dialaddr *restrict addr, const size_t num_proxy)
{
	struct dialreq *restrict req = malloc(
		sizeof(struct dialreq) + sizeof(struct proxy_req) * num_proxy);
	if (req == NULL) {
		return NULL;
	}
	req->addr = *addr;
	req->num_proxy = 0;
	return req;
}

bool dialreq_proxy(
	struct dialreq *restrict req, const char *addr, size_t addrlen)
{
	char buf[1024]; /* should be more than enough */
	if (addrlen >= sizeof(buf)) {
		LOGE_F("proxy too long: \"%s\"", addr);
		return false;
	}
	memcpy(buf, addr, addrlen + 1);
	struct url uri;
	if (!url_parse(buf, &uri)) {
		LOGE_F("unable to parse proxy: \"%s\"", addr);
		return false;
	}
	enum proxy_protocol protocol;
	if (uri.defacto != NULL) {
		protocol = PROTO_SOCKS4A;
		uri.host = uri.defacto;
	} else if (strcmp(uri.scheme, "http") == 0) {
		protocol = PROTO_HTTP;
	} else if (
		strcmp(uri.scheme, "socks4") == 0 ||
		strcmp(uri.scheme, "socks4a") == 0) {
		protocol = PROTO_SOCKS4A;
	} else if (
		strcmp(uri.scheme, "socks5") == 0 ||
		strcmp(uri.scheme, "socks5h") == 0) {
		protocol = PROTO_SOCKS5;
	} else {
		LOGE_F("dialer: unknown scheme \"%s\"", uri.scheme);
		return false;
	}
	const size_t n = req->num_proxy;
	struct proxy_req *restrict proxy = &req->proxy[n];
	proxy->proto = protocol;
	const size_t hostlen = strlen(uri.host);
	if (!dialaddr_set(&proxy->addr, uri.host, hostlen)) {
		return false;
	}
	req->num_proxy = n + 1;
	return true;
}

void dialreq_free(struct dialreq *restrict req)
{
	free(req);
}

enum dialer_state {
	STATE_INIT,
	STATE_CONNECT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_DONE,
};

static void dialer_cancel(struct dialer *restrict d, struct ev_loop *loop)
{
	if (d->req != NULL) {
		dialreq_free(d->req);
		d->req = NULL;
	}
	switch (d->state) {
	case STATE_INIT:
		break;
	case STATE_CONNECT:
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2: {
		ev_io_stop(loop, &d->w_socket);
		ev_timer_stop(loop, &d->w_timeout);
	} break;
	case STATE_DONE:
		break;
	}
}

static void dialer_fail(struct dialer *restrict d, struct ev_loop *loop)
{
	dialer_cancel(d, loop);
	if (d->fd != -1) {
		(void)close(d->fd);
		d->fd = -1;
	}
	d->state = STATE_INIT;
	d->done_cb.cb(loop, d->done_cb.ctx);
}

static void dialer_finish(struct dialer *restrict d, struct ev_loop *loop)
{
	dialer_cancel(d, loop);
	d->state = STATE_DONE;
	d->done_cb.cb(loop, d->done_cb.ctx);
}

static bool format_host(
	char *buf, const size_t bufsize, const struct dialaddr *restrict addr)
{
	switch (addr->type) {
	case ATYP_INET:
		if (inet_ntop(AF_INET, &addr->in, buf, bufsize) == NULL) {
			const int err = errno;
			LOGE_F("inet_ntop: %s", strerror(err));
			return false;
		}
		break;
	case ATYP_INET6:
		if (inet_ntop(AF_INET6, &addr->in6, buf, bufsize) == NULL) {
			const int err = errno;
			LOGE_F("inet_ntop: %s", strerror(err));
			return false;
		}
		break;
	case ATYP_DOMAIN: {
		const size_t n = addr->domain.len;
		if (bufsize < n + 1) {
			LOGE("buffer not enough");
			return false;
		}
		memcpy(buf, addr->domain.name, n);
		buf[n] = '\0';
	} break;
	default:
		FAIL();
	}
	return true;
}

static bool send_socks4a_req(
	struct dialer *restrict d, const struct dialaddr *restrict addr)
{
	const int fd = d->w_socket.fd;
	unsigned char buf[sizeof(struct socks4_hdr) + 1 + FQDN_MAX_LENGTH + 1];
	write_uint8(buf + offsetof(struct socks4_hdr, version), SOCKS4);
	write_uint8(
		buf + offsetof(struct socks4_hdr, command), SOCKS4CMD_CONNECT);
	write_uint16(buf + offsetof(struct socks4_hdr, port), addr->port);
	write_uint32(
		buf + offsetof(struct socks4_hdr, address),
		UINT32_C(0x000000FF));
	buf[sizeof(struct socks4_hdr)] = 0; /* ident = "" */
	/* including the null-terminator */
	char *host = (char *)(buf + sizeof(struct socks4_hdr) + 1);
	if (!format_host(host, FQDN_MAX_LENGTH + 1, addr)) {
		LOGE("unable to format hostname");
		return false;
	}
	const size_t len = sizeof(struct socks4_hdr) + 1 + strlen(host) + 1;
	LOG_BIN_F(LOG_LEVEL_VERBOSE, buf, len, "send: %zu bytes", len);
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		d->syserr = errno;
		d->err = DIALER_SYSERR;
		return false;
	} else if ((size_t)nsend != len) {
		LOGE_F("short send: %zu < %zu", (size_t)nsend, len);
		d->err = DIALER_PROXYERR;
		return false;
	}
	return true;
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
		FAIL();
	case PROTO_SOCKS4A:
		return send_socks4a_req(d, addr);
	case PROTO_SOCKS5:
		FAIL();
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

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	if (d->buf.len < sizeof(struct socks4_hdr)) {
		return sizeof(struct socks4_hdr) - d->buf.len;
	}
	const unsigned char *hdr = d->buf.data;
	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks4_hdr, version));
	if (version != UINT8_C(0)) {
		d->err = DIALER_PROXYERR;
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks4_hdr, command));
	if (command != SOCKS4RSP_GRANTED) {
		d->err = DIALER_PROXYERR;
		return -1;
	}
	/* protocol finished, remove header */
	if (!consume_rcvbuf(d, sizeof(struct socks4_hdr))) {
		d->err = DIALER_PROXYERR;
		return -1;
	}
	return 0;
}

static int
recv_proxy_rsp(struct dialer *restrict d, const struct proxy_req *restrict req)
{
	switch (req->proto) {
	case PROTO_HTTP:
		d->err = DIALER_PROXYERR;
		return -1;
	case PROTO_SOCKS4A:
		return recv_socks4a_rsp(d);
	case PROTO_SOCKS5:
		d->err = DIALER_PROXYERR;
		return -1;
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
		d->syserr = err;
		d->err = DIALER_SYSERR;
		return -1;
	} else if (nrecv == 0) {
		LOGE_F("dialer_recv: fd=%d early EOF", fd);
		d->err = DIALER_PROXYERR;
		return -1;
	}
	d->buf.len = (size_t)nrecv;
	LOG_BIN_F(
		LOG_LEVEL_VERBOSE, d->buf.data, d->buf.len, "recv: %zu bytes",
		d->buf.len);
	const int want = recv_proxy_rsp(d, req);
	if (want < 0) {
		return want;
	} else if (want == 0) {
		socket_rcvlowat(d->fd, 1);
		return 0;
	}
	if (d->buf.len + (size_t)want > d->buf.cap) {
		LOGE("recv: header too long");
		return -1;
	}
	socket_rcvlowat(fd, (size_t)nrecv + (size_t)want);
	return 1;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);

	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;

	const int ret = dialer_recv(d, fd, &d->req->proxy[d->jump]);
	if (ret < 0) { /* fail */
		dialer_fail(d, loop);
		return;
	} else if (ret > 0) {
		ev_io_start(loop, watcher);
		return;
	}

	d->buf.len = 0;
	d->jump++;
	if (d->jump < d->req->num_proxy) {
		d->state = STATE_HANDSHAKE2;
		if (!send_proxy_req(d)) {
			dialer_fail(d, loop);
			return;
		}
		ev_io_start(loop, watcher);
		return;
	}

	dialer_finish(d, loop);
}

static void
connected_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);
	struct dialer *restrict d = watcher->data;
	const struct dialreq *restrict req = d->req;
	const int fd = watcher->fd;

	int sockerr = 0;
	if (getsockopt(
		    fd, SOL_SOCKET, SO_ERROR, &sockerr,
		    &(socklen_t){ sizeof(sockerr) }) == 0) {
		if (sockerr != 0) {
			d->syserr = sockerr;
			d->err = DIALER_SYSERR;
			dialer_fail(d, loop);
			return;
		}
	} else {
		const int err = errno;
		LOGD_F("SO_ERROR: %s", strerror(err));
	}

	if (d->jump >= req->num_proxy) {
		dialer_finish(d, loop);
		return;
	}

	d->state = STATE_HANDSHAKE1;
	if (!send_proxy_req(d)) {
		dialer_fail(d, loop);
		return;
	}
	ev_io_init(watcher, recv_cb, fd, EV_READ);
	watcher->data = d;
	ev_io_start(loop, watcher);
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
		d->err = DIALER_SYSERR;
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		(void)close(fd);
		d->syserr = err;
		d->err = DIALER_SYSERR;
		return false;
	}
	socket_set_tcp(fd, true, true);
#if WITH_NETDEVICE
	const char *netdev = d->conf->netdev;
	if (netdev != NULL) {
		socket_bind_netdev(fd, netdev);
	}
#endif
	if (connect(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			LOGE_F("connect: %s", strerror(err));
			(void)close(fd);
			d->syserr = err;
			d->err = DIALER_SYSERR;
			return false;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "dialer: CONNECT \"%s\"", addr_str);
	}
	d->fd = fd;

	struct ev_io *restrict w_connect = &d->w_socket;
	ev_io_init(w_connect, connected_cb, fd, EV_WRITE);
	w_connect->data = d;
	ev_io_start(loop, w_connect);

	d->state = STATE_CONNECT;
	return true;
}

static bool connect_domain(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct domain_name *domain)
{
	sockaddr_max_t addr;

	char host[FQDN_MAX_LENGTH + 1];
	memcpy(host, domain->name, domain->len);
	host[domain->len] = '\0';
	if (!resolve_hostname(&addr, host, d->conf->resolve_pf)) {
		return false;
	}

	const struct sockaddr *sa = &addr.sa;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_DEBUG, "resolve: \"%.*s\" is \"%s\"",
		      (int)domain->len, domain->name, addr_str);
	}

	const uint16_t port = d->req->addr.port;
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *restrict in = (struct sockaddr_in *)sa;
		in->sin_port = htons(port);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *restrict in6 = (struct sockaddr_in6 *)sa;
		in6->sin6_port = htons(port);
	} break;
	default:
		FAIL();
	}

	return connect_sa(d, loop, sa);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	d->err = DIALER_TIMEOUT;
	dialer_fail(d, loop);
}

void dialer_init(
	struct dialer *restrict d, const struct config *conf,
	const struct event_cb *cb)
{
	d->conf = conf;
	d->done_cb = *cb;
	d->fd = -1;
	d->jump = 0;
	BUF_INIT(d->buf, sizeof(d->buf.data));
	d->req = NULL;
	d->state = STATE_INIT;
	{
		struct ev_timer *restrict w_timeout = &d->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
		w_timeout->data = d;
	}
}

bool dialer_start(
	struct dialer *restrict d, struct ev_loop *restrict loop,
	struct dialreq *restrict req)
{
	d->req = req;
	d->syserr = 0;
	d->err = DIALER_SUCCESS;
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
			return false;
		}
	} break;
	case ATYP_INET6: {
		struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET,
			.sin6_addr = addr->in6,
			.sin6_port = htons(addr->port),
		};
		if (!connect_sa(d, loop, (struct sockaddr *)&in6)) {
			return false;
		}
	} break;
	case ATYP_DOMAIN: {
		if (!connect_domain(d, loop, &addr->domain)) {
			return false;
		}
	} break;
	default:
		FAIL();
	}
	ev_timer_start(loop, &d->w_timeout);
	return true;
}

int dialer_get(struct dialer *d)
{
	assert(d->state == STATE_DONE);
	return d->fd;
}

const char *dialer_strerror(struct dialer *d)
{
	switch (d->err) {
	case DIALER_SUCCESS:
		return NULL;
	case DIALER_SYSERR:
		return strerror(d->syserr);
	case DIALER_TIMEOUT:
		return "connection timeout";
	case DIALER_PROXYERR:
		return "protocol error";
	default:
		break;
	}
	FAIL();
}

void dialer_stop(struct dialer *restrict d, struct ev_loop *loop)
{
	dialer_cancel(d, loop);
	if (d->fd != -1) {
		(void)close(d->fd);
		d->fd = -1;
	}
	d->state = STATE_INIT;
}
