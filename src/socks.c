/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "proto/socks.h"
#include "dialer.h"
#include "resolver.h"
#include "ruleset.h"
#include "transfer.h"
#include "sockutil.h"
#include "stats.h"
#include "util.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define SOCKS_BUF_SIZE 1024

enum socks_state {
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_CONNECT,
	STATE_CONNECTED,
};

static struct stats stats = { 0 };

struct socks_ctx {
	int accepted_fd, dialed_fd;
	enum socks_state state;
	union {
		/* during handshake */
		struct {
			const struct config *conf;
			struct ev_timer w_timeout;
			struct ev_io watcher;
			struct dialaddr addr;
			unsigned char *next;
			struct {
				BUFFER_HDR;
				unsigned char data[SOCKS_BUF_SIZE];
			} rbuf;
			struct ruleset *ruleset;
			struct dialer dialer;
		};
		/* connected */
		struct {
			struct transfer uplink, downlink;
		};
	};
};

static void
socks_stop(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
		ev_timer_stop(loop, &ctx->w_timeout);
		ev_io_stop(loop, &ctx->watcher);
		stats.num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_timer_stop(loop, &ctx->w_timeout);
		dialer_stop(&ctx->dialer, loop);
		stats.num_halfopen--;
		return;
	case STATE_CONNECTED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		return;
	default:
		break;
	}
	FAIL();
}

static void socks_free(struct socks_ctx *restrict ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->accepted_fd != -1) {
		(void)close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		(void)close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	free(ctx);
}

static void xfer_done_cb(struct ev_loop *loop, void *ctx)
{
	socks_stop(loop, ctx);
	socks_free(ctx);
}

static bool send_rsp(const int fd, const void *buf, const size_t len)
{
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		/* TODO: review this */
		const int err = errno;
		LOGE_F("send: fd=%d %s", fd, strerror(err));
		return false;
	} else if ((size_t)nsend != len) {
		LOGE_F("send: fd=%d short send", fd);
		return false;
	}
	return true;
}

static void socks4_sendrsp(struct socks_ctx *restrict ctx, const uint8_t rsp)
{
	struct socks4_hdr hdr = (struct socks4_hdr){
		.version = 0,
		.command = rsp,
	};
	(void)send_rsp(ctx->accepted_fd, &hdr, sizeof(hdr));
}

static void socks5_sendrsp(struct socks_ctx *restrict ctx, uint8_t rsp, int err)
{
	switch (err) {
	case 0:
		break;
	case ENETUNREACH:
		rsp = SOCKS5RSP_NETUNREACH;
		break;
	case EHOSTUNREACH:
		rsp = SOCKS5RSP_HOSTUNREACH;
		break;
	case ECONNREFUSED:
		rsp = SOCKS5RSP_CONNREFUSED;
		break;
	default:
		rsp = SOCKS5RSP_FAIL;
		break;
	}

	sockaddr_max_t addr = {
		.sa.sa_family = AF_INET,
	};
	socklen_t addrlen = sizeof(addr);
	if (ctx->dialed_fd != -1) {
		if (getsockname(ctx->dialed_fd, &addr.sa, &addrlen) != 0) {
			err = errno;
			LOGE_F("getsockname: %s", strerror(err));
		}
	}
	struct {
		struct socks5_hdr hdr;
		unsigned char addr[sizeof(struct in6_addr) + sizeof(in_port_t)];
	} buf;
	buf.hdr = (struct socks5_hdr){
		.version = SOCKS5,
		.command = rsp,
	};
	size_t len = sizeof(struct socks5_hdr);
	switch (addr.sa.sa_family) {
	case AF_INET:
		buf.hdr.addrtype = SOCKS5ADDR_IPV4;
		memcpy(buf.addr, &addr.in.sin_addr, sizeof(addr.in.sin_addr));
		memcpy(buf.addr + sizeof(addr.in.sin_addr), &addr.in.sin_port,
		       sizeof(addr.in.sin_port));
		len += sizeof(addr.in.sin_addr) + sizeof(addr.in.sin_port);
		break;
	case AF_INET6:
		buf.hdr.addrtype = SOCKS5ADDR_IPV6;
		memcpy(buf.addr, &addr.in6.sin6_addr,
		       sizeof(addr.in6.sin6_addr));
		memcpy(buf.addr + sizeof(addr.in6.sin6_addr),
		       &addr.in6.sin6_port, sizeof(addr.in6.sin6_port));
		len += sizeof(addr.in6.sin6_addr) + sizeof(addr.in6.sin6_port);
		break;
	default:
		FAIL();
	}
	(void)send_rsp(ctx->accepted_fd, &buf, len);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct socks_ctx *restrict ctx = watcher->data;
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
		LOGW("handshake timeout");
		break;
	case STATE_CONNECT: {
		const uint8_t version = read_uint8(ctx->rbuf.data);
		if (version == SOCKS5) {
			socks5_sendrsp(ctx, SOCKS5RSP_TTLEXPIRED, 0);
		}
	} break;
	case STATE_CONNECTED:
		ev_timer_stop(loop, watcher);
		return;
	default:
		FAIL();
	}
	socks_stop(loop, ctx);
	socks_free(ctx);
}

static void socks_send_rsp(struct socks_ctx *restrict ctx, const int err)
{
	const uint8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		socks4_sendrsp(
			ctx, err == 0 ? SOCKS4RSP_GRANTED : SOCKS4RSP_REJECTED);
		return;
	case SOCKS5:
		socks5_sendrsp(ctx, err == 0 ? SOCKS5RSP_SUCCEEDED : 0, err);
		return;
	default:
		break;
	}
	FAIL();
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct socks_ctx *restrict ctx = data;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		const int err = ctx->dialer.err;
		LOGD_F("dialer failed: %s",
		       err != 0 ? strerror(err) : "unknown");
		socks_send_rsp(ctx, err);
		socks_stop(loop, ctx);
		socks_free(ctx);
		return;
	}
	LOGV_F("dialer: connected fd=%d", fd);
	ctx->dialed_fd = fd;
	socks_send_rsp(ctx, 0);
	socks_stop(loop, ctx);
	ctx->state = STATE_CONNECTED;
	struct event_cb cb = {
		.cb = xfer_done_cb,
		.ctx = ctx,
	};
	transfer_init(&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd);
	transfer_init(&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static unsigned char *find_zero(unsigned char *s, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (s[i] == 0) {
			return s + i;
		}
	}
	return NULL;
}

static int socks4a_parse(struct socks_ctx *restrict ctx)
{
	unsigned char *zero = find_zero(ctx->next, ctx->rbuf.len);
	if (zero == NULL) {
		return 1;
	}
	const size_t namelen = (size_t)(zero - ctx->next);
	if (namelen > FQDN_MAX_LENGTH) {
		return 1;
	}

	ctx->addr.type = ATYP_DOMAIN;
	struct domain_name *restrict domain = &ctx->addr.domain;
	domain->len = (uint8_t)namelen;
	memcpy(domain->name, ctx->next, namelen);
	ctx->addr.port =
		read_uint16(ctx->rbuf.data + offsetof(struct socks4_hdr, port));
	return 0;
}

static int socks4_parse(struct socks_ctx *restrict ctx)
{
	if (ctx->rbuf.len <= sizeof(struct socks4_hdr)) {
		return 1;
	}
	const uint8_t command =
		ctx->rbuf.data[offsetof(struct socks4_hdr, command)];
	if (command != SOCKS4CMD_CONNECT) {
		LOGW_F("unsupported socks4 command: %" PRIu8, command);
		(void)socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return -1;
	}
	unsigned char *terminator = find_zero(
		ctx->rbuf.data + sizeof(struct socks4_hdr), ctx->rbuf.len);
	if (terminator == NULL) {
		return 1;
	}
	const uint32_t ip = read_uint32(
		ctx->rbuf.data + offsetof(struct socks4_hdr, address));
	const uint32_t mask = UINT32_C(0xFFFFFF00);
	if (!(ip & mask) && (ip & ~mask)) {
		ctx->state = STATE_HANDSHAKE2;
		ctx->next = terminator + 1;
		return socks4a_parse(ctx);
	}

	ctx->addr.type = ATYP_INET;
	memcpy(&ctx->addr.in,
	       ctx->rbuf.data + offsetof(struct socks4_hdr, address),
	       sizeof(ctx->addr.in));
	ctx->addr.port =
		read_uint16(ctx->rbuf.data + offsetof(struct socks4_hdr, port));
	return 0;
}

static int socks5_parse(struct socks_ctx *restrict ctx)
{
	const uint8_t n = read_uint8(
		ctx->rbuf.data + offsetof(struct socks5_auth_req, nmethods));
	const unsigned char *hdr =
		ctx->rbuf.data + sizeof(struct socks5_auth_req) + n;
	const size_t len = ctx->rbuf.len - (sizeof(struct socks5_auth_req) + n);
	size_t want = sizeof(struct socks5_hdr);
	if (len < want) {
		return 1;
	}
	const uint8_t command = hdr[offsetof(struct socks5_hdr, command)];
	if (command != SOCKS5CMD_CONNECT) {
		(void)socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT, 0);
		return -1;
	}
	const uint8_t addrtype = hdr[offsetof(struct socks5_hdr, addrtype)];
	switch (addrtype) {
	case SOCKS5ADDR_IPV4:
		want += sizeof(struct in_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_IPV6:
		want += sizeof(struct in6_addr) + sizeof(in_port_t);
		break;
	case SOCKS5ADDR_DOMAIN:
		want += 1;
		if (len < want) {
			return 1;
		}
		want += read_uint8(hdr + sizeof(struct socks5_hdr));
		break;
	default:
		(void)socks5_sendrsp(ctx, SOCKS5RSP_ATYPNOSUPPORT, 0);
		return -1;
	}
	if (len < want) {
		return 1;
	}
	const unsigned char *rawaddr = hdr + sizeof(struct socks5_hdr);
	switch (addrtype) {
	case SOCKS5ADDR_IPV4: {
		ctx->addr.type = ATYP_INET;
		memcpy(&ctx->addr.in, rawaddr, sizeof(ctx->addr.in));
		rawaddr += sizeof(struct in_addr);
		ctx->addr.port = read_uint16(rawaddr);
	} break;
	case SOCKS5ADDR_IPV6: {
		ctx->addr.type = ATYP_INET6;
		memcpy(&ctx->addr.in6, rawaddr, sizeof(ctx->addr.in6));
		rawaddr += sizeof(struct in6_addr);
		ctx->addr.port = read_uint16(rawaddr);
	} break;
	case SOCKS5ADDR_DOMAIN: {
		const uint8_t addrlen = read_uint8(rawaddr);
		rawaddr++;
		ctx->addr.type = ATYP_DOMAIN;
		struct domain_name *restrict domain = &ctx->addr.domain;
		domain->len = addrlen;
		memcpy(domain->name, rawaddr, addrlen);
		ctx->addr.port = read_uint16(rawaddr + addrlen);
	} break;
	default:
		return -1;
	}
	return 0;
}

static int socks5_auth(struct socks_ctx *restrict ctx)
{
	const size_t len = ctx->rbuf.len;
	size_t want = sizeof(struct socks5_auth_req);
	if (len < want) {
		return 1;
	}
	const uint8_t n = read_uint8(
		ctx->rbuf.data + offsetof(struct socks5_auth_req, nmethods));
	want += n;
	if (len < want) {
		return 1;
	}
	bool found = false;
	const uint8_t *methods =
		ctx->rbuf.data + sizeof(struct socks5_auth_req);
	for (size_t i = 0; i < n; i++) {
		if (methods[i] == SOCKS5AUTH_NOAUTH) {
			found = true;
			break;
		}
	}
	unsigned char wbuf[sizeof(struct socks5_auth_rsp)];
	write_uint8(wbuf + offsetof(struct socks5_auth_rsp, version), SOCKS5);
	write_uint8(
		wbuf + offsetof(struct socks5_auth_rsp, method),
		found ? SOCKS5AUTH_NOAUTH : SOCKS5AUTH_NOACCEPTABLE);
	if (!send_rsp(ctx->accepted_fd, wbuf, sizeof(wbuf))) {
		return -1;
	}
	if (!found) {
		return -1;
	}
	ctx->next = ctx->rbuf.data + sizeof(struct socks5_auth_req) + n;
	ctx->state = STATE_HANDSHAKE2;
	return socks5_parse(ctx);
}

static int socks_parse(struct socks_ctx *restrict ctx)
{
	if (ctx->rbuf.len < 1) {
		return 1;
	}
	switch (read_uint8(ctx->rbuf.data)) {
	case SOCKS4:
		switch (ctx->state) {
		case STATE_HANDSHAKE1:
			return socks4_parse(ctx);
		case STATE_HANDSHAKE2:
			return socks4a_parse(ctx);
		default:
			break;
		}
		break;
	case SOCKS5:
		switch (ctx->state) {
		case STATE_HANDSHAKE1:
			return socks5_auth(ctx);
		case STATE_HANDSHAKE2:
			return socks5_parse(ctx);
		default:
			break;
		}
		break;
	default:
		break;
	}
	return -1;
}

static int socks_read(struct socks_ctx *restrict ctx, const int fd)
{
	const size_t cap = ctx->rbuf.cap;
	size_t nbrecv = 0;
	while (ctx->rbuf.len < cap) {
		const ssize_t nrecv =
			recv(fd, ctx->rbuf.data + ctx->rbuf.len,
			     cap - ctx->rbuf.len, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("recv: fd=%d %s", fd, strerror(err));
			return -1;
		} else if (nrecv == 0) {
			LOGE_F("recv: fd=%d early EOF", fd);
			return -1;
		}
		ctx->rbuf.len += nrecv;
		nbrecv += nrecv;
	}
	if (nbrecv == 0) {
		return 1;
	}
	const int want = socks_parse(ctx);
	if (want <= 0) {
		return want;
	} else if (ctx->rbuf.len + (size_t)want > cap) {
		LOGE_F("recv: fd=%d header too long", fd);
		return -1;
	}
	return 1;
}

static struct dialreq *make_dialreq(struct socks_ctx *restrict ctx)
{
	if (ctx->ruleset == NULL) {
		return dialreq_new(&ctx->addr, 0);
	}

	char request[FQDN_MAX_LENGTH + 1 + 5 + 1];
	(void)dialaddr_format(&ctx->addr, request, sizeof(request));
	switch (ctx->addr.type) {
	case ATYP_DOMAIN:
		return ruleset_resolve(ctx->ruleset, request);
	case ATYP_INET:
		return ruleset_route(ctx->ruleset, request);
	case ATYP_INET6:
		return ruleset_route6(ctx->ruleset, request);
	default:
		LOGE_F("unsupported address type: %d", ctx->addr.type);
		break;
	}
	return NULL;
}

static void
socks_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct socks_ctx *restrict ctx = watcher->data;
	const int ret = socks_read(ctx, watcher->fd);
	if (ret < 0) {
		socks_stop(loop, ctx);
		socks_free(ctx);
		return;
	} else if (ret > 0) {
		return;
	}

	ev_io_stop(loop, watcher);
	stats.num_request++;

	struct dialreq *req = make_dialreq(ctx);
	if (req == NULL) {
		socks_stop(loop, ctx);
		socks_free(ctx);
		return;
	}

	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char raddr[FQDN_MAX_LENGTH + 1 + 5 + 1];
		(void)dialaddr_format(&req->addr, raddr, sizeof(raddr));
		LOG_F(LOG_LEVEL_INFO, "socks: CONNECT %s", raddr);
	}

	ctx->state = STATE_CONNECT;
	if (!dialer_start(&ctx->dialer, loop, req)) {
		socks_stop(loop, ctx);
		socks_free(ctx);
		return;
	}
}

static struct socks_ctx *socks_new(
	const int accepted_fd, struct ruleset *ruleset,
	const struct config *conf)
{
	struct socks_ctx *restrict ctx = malloc(sizeof(struct socks_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->accepted_fd = accepted_fd;
	ctx->dialed_fd = -1;
	ctx->state = STATE_HANDSHAKE1;
	ctx->conf = conf;
	ctx->ruleset = ruleset;
	buf_init(&ctx->rbuf, SOCKS_BUF_SIZE);
	struct ev_io *restrict w_read = &ctx->watcher;
	ev_io_init(w_read, socks_recv_cb, accepted_fd, EV_READ);
	w_read->data = ctx;
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
	w_timeout->data = ctx;
	dialer_init(
		&ctx->dialer, ctx->conf,
		&(struct event_cb){
			.cb = dialer_cb,
			.ctx = ctx,
		});
	return ctx;
}

static void socks_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	struct ev_io *restrict w_read = &ctx->watcher;
	ev_io_start(loop, w_read);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_start(loop, w_timeout);
	stats.num_halfopen++;
}

void socks_serve(
	struct ev_loop *loop, struct server *s, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	UNUSED(accepted_sa);
	struct socks_ctx *restrict ctx =
		socks_new(accepted_fd, s->ruleset, s->conf);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	socks_start(loop, ctx);
}

void socks_read_stats(struct stats *restrict out_stats)
{
	*out_stats = stats;
}
