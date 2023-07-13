#include "dialer.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/addr.h"
#include "net/url.h"
#include "proto/socks.h"
#include "conf.h"
#include "resolver.h"
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
	STATE_RESOLVE,
	STATE_CONNECT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_DONE,
};

static void
dialer_reset(struct dialer *restrict d, struct ev_loop *loop, const int state)
{
	if (d->req != NULL) {
		dialreq_free(d->req);
		d->req = NULL;
	}
	switch (d->state) {
	case STATE_INIT:
		break;
	case STATE_RESOLVE:
		resolver_stop(&d->resolver, loop);
		ev_timer_stop(loop, &d->w_timeout);
		break;
	case STATE_CONNECT:
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2: {
		ev_io_stop(loop, &d->w_recv);
		ev_timer_stop(loop, &d->w_timeout);
		ev_timer_stop(loop, &d->w_ticker);
		if (d->fd > 0) {
			(void)close(d->fd);
			d->fd = -1;
		}
	} break;
	case STATE_DONE:
		break;
	}
	d->state = state;
}

static void dialer_finish(struct dialer *restrict d, struct ev_loop *loop)
{
	dialer_reset(d, loop, STATE_DONE);
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
	const int fd = d->w_recv.fd;
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

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	if (d->buf.len < sizeof(struct socks4_hdr)) {
		return 1;
	}
	struct socks4_hdr hdr;
	hdr.version =
		read_uint8(d->buf.data + offsetof(struct socks4_hdr, version));
	if (hdr.version != UINT8_C(0)) {
		d->err = DIALER_PROXYERR;
		return -1;
	}
	hdr.command =
		read_uint8(d->buf.data + offsetof(struct socks4_hdr, command));
	if (hdr.command != SOCKS4RSP_GRANTED) {
		d->err = DIALER_PROXYERR;
		return -1;
	}
	/* consume the header */
	const ssize_t nrecv =
		recv(d->fd, (void *)&hdr, sizeof(struct socks4_hdr), 0);
	if (nrecv != (ssize_t)sizeof(struct socks4_hdr)) {
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
	unsigned char *data = d->buf.data;
	const size_t cap = d->buf.cap;
	const ssize_t nrecv = recv(fd, data, cap, MSG_PEEK);
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
	const int want = recv_proxy_rsp(d, req);
	if (want <= 0) {
		return want;
	}
	return 1;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;
	struct ev_timer *restrict w_ticker = &d->w_ticker;

	const int ret = dialer_recv(d, fd, &d->req->proxy[d->jump]);
	if (ret > 0) { /* wait for more */
		ev_io_stop(loop, watcher);
		if (!ev_is_active(w_ticker)) {
			ev_timer_start(loop, w_ticker);
		}
		return;
	} else if (ret < 0) { /* fail */
		dialer_finish(d, loop);
		return;
	}

	d->buf.len = 0;
	d->jump++;
	if (d->jump < d->req->num_proxy) {
		d->state = STATE_HANDSHAKE2;
		if (!send_proxy_req(d)) {
			dialer_finish(d, loop);
			return;
		}
		return;
	}

	ev_io_stop(loop, &d->w_recv);
	ev_timer_stop(loop, &d->w_timeout);
	ev_timer_stop(loop, &d->w_ticker);
	d->state = STATE_DONE;
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
			dialer_finish(d, loop);
			return;
		}
	} else {
		const int err = errno;
		LOGD_F("SO_ERROR: %s", strerror(err));
	}

	if (d->jump >= req->num_proxy) {
		d->state = STATE_DONE;
		ev_timer_stop(loop, &d->w_timeout);
		dialer_finish(d, loop);
		return;
	}

	d->state = STATE_HANDSHAKE1;
	if (!send_proxy_req(d)) {
		dialer_finish(d, loop);
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

	struct ev_io *restrict w_connect = &d->w_recv;
	ev_io_init(w_connect, connected_cb, fd, EV_WRITE);
	w_connect->data = d;
	ev_io_start(loop, w_connect);

	d->state = STATE_CONNECT;
	return true;
}

static void resolve_cb(struct ev_loop *loop, void *data)
{
	struct dialer *restrict d = data;
	const struct sockaddr *sa = resolver_get(&d->resolver);
	if (sa == NULL) {
		LOGD("dialer resolve failed");
		dialer_stop(d, loop);
		return;
	}
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "dialer: resolve \"%s\"", addr_str);
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
		LOGE_F("unsupported address family: %d", sa->sa_family);
		dialer_finish(d, loop);
		return;
	}

	if (!connect_sa(d, loop, sa)) {
		LOGD("dialer connect failed");
		dialer_finish(d, loop);
	}
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	d->err = DIALER_TIMEOUT;
	dialer_finish(d, loop);
}

static void
ticker_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	struct ev_io *restrict w_recv = &d->w_recv;
	if (!ev_is_active(w_recv)) {
		ev_io_start(loop, w_recv);
	}
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
	resolver_init(
		&d->resolver, conf->resolve_pf,
		&(struct event_cb){
			.cb = resolve_cb,
			.ctx = d,
		});
	{
		struct ev_timer *restrict w_timeout = &d->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
		w_timeout->data = d;

		struct ev_timer *restrict w_ticker = &d->w_ticker;
		ev_timer_init(w_ticker, ticker_cb, 0.1, 0.1);
		w_ticker->data = d;
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
		if (!resolver_start(&d->resolver, loop, &addr->domain)) {
			return false;
		}
		d->state = STATE_RESOLVE;
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
	dialer_reset(d, loop, STATE_INIT);
}
