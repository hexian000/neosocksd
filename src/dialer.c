#include "dialer.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/addr.h"
#include "proto/socks.h"
#include "conf.h"
#include "resolver.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <errno.h>
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
		LOGD_F("address too long: %s", s);
		return false;
	}
	memcpy(buf, s, len);
	buf[len] = '\0';
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		LOGD_F("invalid address: %s", s);
		return false;
	}
	const size_t hostlen = strlen(host);
	if (hostlen > FQDN_MAX_LENGTH) {
		LOGD_F("hostname too long: %s", host);
		return false;
	}
	if (sscanf(port, "%" SCNu16, &addr->port) != 1) {
		LOGD_F("unable to parse port number: %" PRIu16, addr->port);
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
		LOGOOM();
		return NULL;
	}
	req->addr = *addr;
	req->num_proxy = 0;
	return req;
}

bool dialreq_proxy(
	struct dialreq *restrict req, enum proxy_protocol protocol,
	const char *addr, size_t addrlen)
{
	char *s = malloc(addrlen + 1);
	if (s == NULL) {
		LOGOOM();
		return false;
	}
	const size_t n = req->num_proxy;
	req->proxy[n] = (struct proxy_req){
		.proto = protocol,
		.addr = strncpy(s, addr, addrlen + 1),
		.addrlen = addrlen,
	};
	req->num_proxy = n + 1;
	return true;
}

void dialreq_free(struct dialreq *restrict req)
{
	for (size_t i = 0; i < req->num_proxy; i++) {
		free(req->proxy[i].addr);
	}
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
		break;
	case STATE_CONNECT:
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2: {
		struct ev_io *restrict watcher = &d->watcher;
		ev_io_stop(loop, watcher);
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

static void
dialer_finish(struct dialer *restrict d, struct ev_loop *loop, const bool ok)
{
	if (ok) {
		d->state = STATE_DONE;
	}
	dialer_reset(d, loop, STATE_DONE);
	d->done_cb.cb(loop, d->done_cb.ctx);
}

#define MAX_ADDRLEN ((size_t)(256 + 1 + 5))

static bool send_socks4a_req(struct dialer *restrict d)
{
	const struct proxy_req *restrict req = &d->req->proxy[d->jump];
	const int fd = d->watcher.fd;
	uint16_t port;
	char addr[MAX_ADDRLEN + 1];
	(void)memcpy(addr, req->addr, req->addrlen);
	addr[req->addrlen] = '\0';
	char *host, *service;
	if (!splithostport(addr, &host, &service)) {
		LOGD_F("failed parsing address: %s", addr);
		return false;
	}
	if (sscanf(service, "%" SCNu16, &port) != 1) {
		LOGD_F("failed parsing address: %s", addr);
		return false;
	}

	unsigned char buf[sizeof(struct socks4_hdr) + 1 + MAX_ADDRLEN + 1];
	write_uint8(buf + offsetof(struct socks4_hdr, version), SOCKS4);
	write_uint8(
		buf + offsetof(struct socks4_hdr, command), SOCKS4CMD_CONNECT);
	write_uint16(buf + offsetof(struct socks4_hdr, port), port);
	write_uint32(
		buf + offsetof(struct socks4_hdr, address),
		UINT32_C(0x000000FF));
	buf[sizeof(struct socks4_hdr)] = 0; /* ident = "" */
	(void)strcpy((char *)(buf + sizeof(struct socks4_hdr) + 1), host);
	const size_t len = sizeof(struct socks4_hdr) + 1 + req->addrlen + 1;
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		d->err = errno;
		return false;
	} else if ((size_t)nsend != len) {
		LOGD_F("short send: %zu < %zu", (size_t)nsend, len);
		return false;
	}
	return true;
}

static bool send_proxy_req(struct dialer *restrict d)
{
	const struct proxy_req *restrict req = &d->req->proxy[d->jump];
	LOGD_F("dialer: CONNECT %zu/%zu: \"%s\", protocol=%d", d->jump + 1,
	       d->req->num_proxy, req->addr, req->proto);
	switch (req->proto) {
	case PROTO_SOCKS4A:
		return send_socks4a_req(d);
	}
	return false;
}

static int recv_socks4a_rsp(struct dialer *restrict d)
{
	const size_t len = sizeof(struct socks4_hdr);
	if (d->buf.len < len) {
		return 1;
	}
	const uint8_t version =
		read_uint8(d->buf.data + offsetof(struct socks4_hdr, version));
	if (version != UINT8_C(0)) {
		return -1;
	}
	const uint8_t command =
		read_uint8(d->buf.data + offsetof(struct socks4_hdr, command));
	if (command != SOCKS4RSP_GRANTED) {
		return -1;
	}
	return 0;
}

static int
recv_proxy_rsp(struct dialer *restrict d, const struct proxy_req *restrict req)
{
	int ret = -1;
	switch (req->proto) {
	case PROTO_SOCKS4A:
		ret = recv_socks4a_rsp(d);
		if (ret < 0) {
			LOGE_F("dialer: SOCKS4A protocol error \"%s\"",
			       req->addr);
		}
		break;
	}
	return ret;
}

static int dialer_recv(
	struct dialer *restrict d, const int fd,
	const struct proxy_req *restrict req)
{
	size_t nbrecv = 0;
	unsigned char *data = d->buf.data + d->buf.len;
	size_t cap = d->buf.cap - d->buf.len;
	while (cap > 0) {
		const ssize_t nrecv = recv(fd, data, cap, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			d->err = err;
			return -1;
		} else if (nrecv == 0) {
			LOGD_F("dialer_recv: fd=%d early EOF", fd);
			return -1;
		}
		data += nrecv;
		cap -= nrecv;
		nbrecv += nrecv;
	}
	if (nbrecv == 0) {
		return 1;
	}
	d->buf.len += nbrecv;
	const int want = recv_proxy_rsp(d, req);
	if (want <= 0) {
		return want;
	} else if (d->buf.len + (size_t)want > cap) {
		LOGD_F("dialer_recv: fd=%d header too long", fd);
		return -1;
	}
	return 1;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;

	const int ret = dialer_recv(d, fd, &d->req->proxy[d->jump]);
	if (ret > 0) { /* want more */
		return;
	} else if (ret < 0) { /* fail */
		dialer_finish(d, loop, false);
		return;
	}

	d->jump++;
	d->buf.len = 0;
	if (d->jump < d->req->num_proxy) {
		d->state = STATE_HANDSHAKE2;
		if (!send_proxy_req(d)) {
			dialer_finish(d, loop, false);
			return;
		}
		return;
	}

	ev_io_stop(loop, watcher);
	dialer_finish(d, loop, true);
}

static void
connected_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);
	struct dialer *restrict d = watcher->data;
	const int fd = watcher->fd;

	int sockerr = 0;
	if (getsockopt(
		    fd, SOL_SOCKET, SO_ERROR, &sockerr,
		    &(socklen_t){ sizeof(sockerr) }) == 0) {
		if (sockerr != 0) {
			d->err = sockerr;
			dialer_finish(d, loop, false);
			return;
		}
	} else {
		const int err = errno;
		LOGD_F("SO_ERROR: %s", strerror(err));
	}

	if (d->jump < d->req->num_proxy) {
		d->state = STATE_HANDSHAKE1;
		if (!send_proxy_req(d)) {
			dialer_finish(d, loop, false);
			return;
		}
		ev_io_init(watcher, recv_cb, fd, EV_READ);
		watcher->data = d;
		ev_io_start(loop, watcher);
		return;
	}

	dialer_finish(d, loop, true);
}

static bool connect_sa(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct sockaddr *sa)
{
	const int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGD_F("socket: %s", strerror(err));
		d->err = err;
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGD_F("fcntl: %s", strerror(err));
		(void)close(fd);
		d->err = err;
		return false;
	}
	socket_set_tcp(fd, true, false);
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
			d->err = err;
			return false;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "dialer: CONNECT \"%s\"", addr_str);
	}
	d->fd = fd;

	struct ev_io *restrict w_connect = &d->watcher;
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
		LOGE_F("unsupport address family: %d", sa->sa_family);
		dialer_finish(d, loop, false);
		return;
	}

	if (!connect_sa(d, loop, sa)) {
		LOGD("dialer connect failed");
		dialer_finish(d, loop, false);
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
	buf_init(&d->buf, DIALER_BUF_SIZE);
	d->req = NULL;
	d->state = STATE_INIT;
	resolver_init(
		&d->resolver, d->conf->resolve_pf,
		&(struct event_cb){
			.cb = resolve_cb,
			.ctx = d,
		});
}

bool dialer_start(
	struct dialer *restrict d, struct ev_loop *restrict loop,
	struct dialreq *restrict req)
{
	d->req = req;
	d->err = 0;
	switch (req->addr.type) {
	case ATYP_INET: {
		struct sockaddr_in in = {
			.sin_family = AF_INET,
			.sin_addr = req->addr.in,
			.sin_port = htons(req->addr.port),
		};
		return connect_sa(d, loop, (struct sockaddr *)&in);
	}
	case ATYP_INET6: {
		struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET,
			.sin6_addr = req->addr.in6,
			.sin6_port = htons(req->addr.port),
		};
		return connect_sa(d, loop, (struct sockaddr *)&in6);
	}
	case ATYP_DOMAIN:
		break;
	default:
		FAIL();
	}

	if (!resolver_start(&d->resolver, loop, &req->addr.domain)) {
		return false;
	}
	d->state = STATE_RESOLVE;
	return true;
}

int dialer_get(struct dialer *d)
{
	assert(d->state == STATE_DONE);
	return d->fd;
}

void dialer_stop(struct dialer *restrict d, struct ev_loop *loop)
{
	dialer_reset(d, loop, STATE_INIT);
}
