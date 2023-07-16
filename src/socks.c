/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"
#include "server.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "proto/socks.h"
#include "dialer.h"
#include "ruleset.h"
#include "transfer.h"
#include "sockutil.h"
#include "util.h"

#include <assert.h>
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

enum socks_state {
	STATE_INIT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct socks_ctx {
	struct server *s;
	int accepted_fd, dialed_fd;
	enum socks_state state;
	sockaddr_max_t accepted_sa;
	struct ev_timer w_timeout;
	union {
		/* during handshake */
		struct {
			struct ev_io watcher;
			struct dialaddr addr;
			unsigned char *next;
			struct {
				BUFFER_HDR;
				unsigned char data[SOCKS_MAX_LENGTH];
			} rbuf;
			struct dialer dialer;
		};
		/* connected */
		struct {
			struct transfer uplink, downlink;
		};
	};
};

#define SOCKS_CTX_LOG_F(level, ctx, format, ...)                               \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char laddr[64];                                                \
		format_sa(&(ctx)->accepted_sa.sa, laddr, sizeof(laddr));       \
		if ((ctx)->state == STATE_CONNECT) {                           \
			char raddr[64];                                        \
			(void)dialaddr_format(                                 \
				&(ctx)->addr, raddr, sizeof(raddr));           \
			LOG_F(level, "\"%s\" -> \"%s\": " format, laddr,       \
			      raddr, __VA_ARGS__);                             \
		} else {                                                       \
			LOG_F(level, "\"%s\": " format, laddr, __VA_ARGS__);   \
		}                                                              \
	} while (0)
#define SOCKS_CTX_LOG(level, ctx, message)                                     \
	SOCKS_CTX_LOG_F(level, ctx, "%s", message)

static void
socks_ctx_stop(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
		ev_io_stop(loop, &ctx->watcher);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_stop(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_CONNECTED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		break;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	default:
		FAIL();
	}
	SOCKS_CTX_LOG_F(
		LOG_LEVEL_INFO, ctx, "closed, %zu active", stats->num_sessions);
}

static void socks_ctx_free(struct socks_ctx *restrict ctx)
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

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct socks_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_CLOSED ||
	    ctx->downlink.state == XFER_CLOSED) {
		socks_ctx_stop(loop, ctx);
		socks_ctx_free(ctx);
		return;
	}
	if (ctx->state == STATE_CONNECTED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		ctx->state = STATE_ESTABLISHED;
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
		ev_timer_stop(loop, &ctx->w_timeout);
		return;
	}
}

static bool
send_rsp(struct socks_ctx *restrict ctx, const void *buf, const size_t len)
{
	LOG_BIN_F(LOG_LEVEL_VERBOSE, buf, len, "send_rsp: %zu bytes", len);
	const ssize_t nsend = send(ctx->accepted_fd, buf, len, 0);
	if (nsend < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx, "send: %s", strerror(err));
		return false;
	} else if ((size_t)nsend != len) {
		SOCKS_CTX_LOG(LOG_LEVEL_ERROR, ctx, "send: short send");
		return false;
	}
	return true;
}

static void socks4_sendrsp(struct socks_ctx *restrict ctx, const uint8_t rsp)
{
	unsigned char buf[sizeof(struct socks4_hdr)] = { 0 };
	write_uint8(buf + offsetof(struct socks4_hdr, version), 0);
	write_uint8(buf + offsetof(struct socks4_hdr, command), rsp);
	(void)send_rsp(ctx, buf, sizeof(buf));
}

static void socks5_sendrsp(struct socks_ctx *restrict ctx, uint8_t rsp)
{
	sockaddr_max_t addr = {
		.sa.sa_family = AF_INET,
	};
	socklen_t addrlen = sizeof(addr);
	if (ctx->dialed_fd != -1) {
		if (getsockname(ctx->dialed_fd, &addr.sa, &addrlen) != 0) {
			const int err = errno;
			LOGE_F("getsockname: %s", strerror(err));
		}
	}
	unsigned char
		buf[sizeof(struct socks5_hdr) + sizeof(struct in6_addr) +
		    sizeof(in_port_t)];
	unsigned char *const hdr = buf;

	write_uint8(hdr + offsetof(struct socks5_hdr, version), SOCKS5);
	write_uint8(hdr + offsetof(struct socks5_hdr, command), rsp);

	size_t len = sizeof(struct socks5_hdr);
	unsigned char *const addrbuf = buf + len;
	switch (addr.sa.sa_family) {
	case AF_INET: {
		write_uint8(
			hdr + offsetof(struct socks5_hdr, addrtype),
			SOCKS5ADDR_IPV4);
		memcpy(addrbuf, &addr.in.sin_addr, sizeof(addr.in.sin_addr));
		len += sizeof(addr.in.sin_addr);
		unsigned char *const portbuf = buf + len;
		memcpy(portbuf, &addr.in.sin_port, sizeof(addr.in.sin_port));
		len += sizeof(addr.in.sin_port);
	} break;
	case AF_INET6: {
		write_uint8(
			hdr + offsetof(struct socks5_hdr, addrtype),
			SOCKS5ADDR_IPV6);
		memcpy(addrbuf, &addr.in6.sin6_addr,
		       sizeof(addr.in6.sin6_addr));
		len += sizeof(addr.in6.sin6_addr);
		unsigned char *const portbuf = buf + len;
		memcpy(portbuf, &addr.in6.sin6_port,
		       sizeof(addr.in6.sin6_port));
		len += sizeof(addr.in6.sin6_port);
	} break;
	default:
		FAIL();
	}
	(void)send_rsp(ctx, &buf, len);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct socks_ctx *restrict ctx = watcher->data;
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
		SOCKS_CTX_LOG(LOG_LEVEL_WARNING, ctx, "handshake timeout");
		break;
	case STATE_CONNECT: {
		const uint8_t version = read_uint8(ctx->rbuf.data);
		if (version == SOCKS5) {
			socks5_sendrsp(ctx, SOCKS5RSP_TTLEXPIRED);
		}
	} break;
	case STATE_CONNECTED:
		SOCKS_CTX_LOG(LOG_LEVEL_WARNING, ctx, "protocol timeout");
		break;
	case STATE_ESTABLISHED:
		return;
	default:
		FAIL();
	}
	socks_ctx_stop(loop, ctx);
	socks_ctx_free(ctx);
}

static void socks_sendrsp(struct socks_ctx *restrict ctx, const bool ok)
{
	const uint8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		socks4_sendrsp(
			ctx, ok ? SOCKS4RSP_GRANTED : SOCKS4RSP_REJECTED);
		return;
	case SOCKS5:
		socks5_sendrsp(
			ctx, ok ? SOCKS5RSP_SUCCEEDED : SOCKS5RSP_NOALLOWED);
		return;
	default:
		break;
	}
	FAIL();
}

static uint8_t socks5_err2rsp(const int err)
{
	switch (err) {
	case ENETUNREACH:
		return SOCKS5RSP_NETUNREACH;
	case EHOSTUNREACH:
		return SOCKS5RSP_HOSTUNREACH;
	case ECONNREFUSED:
		return SOCKS5RSP_CONNREFUSED;
	default:
		break;
	}
	return SOCKS5RSP_FAIL;
}

static void socks_senderr(struct socks_ctx *restrict ctx, const int err)
{
	const uint8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return;
	case SOCKS5:
		socks5_sendrsp(ctx, socks5_err2rsp(err));
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
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx, "dialer: %s",
			dialer_strerror(&ctx->dialer));
		socks_senderr(ctx, ctx->dialer.syserr);
		socks_ctx_stop(loop, ctx);
		socks_ctx_free(ctx);
		return;
	}
	ctx->dialed_fd = fd;
	socks_sendrsp(ctx, true);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);

	SOCKS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "connected");

	const struct config *restrict conf = ctx->s->conf;
	struct server_stats *restrict stats = &ctx->s->stats;
	if (conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
		ev_timer_start(loop, w_timeout);
	} else {
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
	}

	struct event_cb cb = {
		.cb = xfer_state_cb,
		.ctx = ctx,
	};
	transfer_init(
		&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static bool consume_rcvbuf(struct socks_ctx *restrict ctx, const size_t n)
{
	LOGV_F("consume_rcvbuf: %zu bytes", n);
	const int fd = ctx->accepted_fd;
	const ssize_t nrecv = recv(fd, ctx->rbuf.data, n, 0);
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

static unsigned char *find_zero(unsigned char *s, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (s[i] == 0) {
			return s + i;
		}
	}
	return NULL;
}

static int socks4a_recv(struct socks_ctx *restrict ctx)
{
	assert(ctx->state == STATE_HANDSHAKE2);
	unsigned char *terminator = find_zero(ctx->next, ctx->rbuf.len);
	if (terminator == NULL) {
		return 1;
	}
	const size_t namelen = (size_t)(terminator - ctx->next);
	if (namelen > FQDN_MAX_LENGTH) {
		return 1;
	}

	ctx->addr.type = ATYP_DOMAIN;
	struct domain_name *restrict domain = &ctx->addr.domain;
	domain->len = (uint8_t)namelen;
	memcpy(domain->name, ctx->next, namelen);
	ctx->addr.port =
		read_uint16(ctx->rbuf.data + offsetof(struct socks4_hdr, port));

	/* protocol finished, remove header */
	if (!consume_rcvbuf(ctx, (size_t)(terminator + 1 - ctx->rbuf.data))) {
		return -1;
	}
	return 0;
}

static int socks4_recv(struct socks_ctx *restrict ctx)
{
	assert(ctx->state == STATE_HANDSHAKE1);
	if (ctx->rbuf.len <= sizeof(struct socks4_hdr)) {
		return sizeof(struct socks4_hdr) - ctx->rbuf.len + 1;
	}
	const uint8_t command = read_uint8(
		ctx->rbuf.data + offsetof(struct socks4_hdr, command));
	if (command != SOCKS4CMD_CONNECT) {
		LOGE_F("unsupported SOCKS4 command: %" PRIu8, command);
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
		return socks4a_recv(ctx);
	}

	ctx->addr.type = ATYP_INET;
	memcpy(&ctx->addr.in,
	       ctx->rbuf.data + offsetof(struct socks4_hdr, address),
	       sizeof(ctx->addr.in));
	ctx->addr.port =
		read_uint16(ctx->rbuf.data + offsetof(struct socks4_hdr, port));

	/* protocol finished, remove header */
	if (!consume_rcvbuf(ctx, (size_t)(terminator + 1 - ctx->rbuf.data))) {
		return -1;
	}
	return 0;
}

static int socks5_req(struct socks_ctx *restrict ctx)
{
	assert(ctx->state == STATE_HANDSHAKE2);
	const unsigned char *hdr = ctx->next;
	const size_t authlen = (size_t)(ctx->next - ctx->rbuf.data);
	const size_t len = ctx->rbuf.len - authlen;
	size_t expected = sizeof(struct socks5_hdr);
	if (len < expected) {
		return (expected - len) + 1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks5_hdr, command));
	if (command != SOCKS5CMD_CONNECT) {
		socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx,
			"SOCKS5: unsupported command %" PRIu8, command);
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
	case SOCKS5ADDR_DOMAIN: {
		expected += 1;
		if (len < expected) {
			return expected - len;
		}
		const uint8_t addrlen =
			read_uint8(hdr + sizeof(struct socks5_hdr));
		expected += (size_t)addrlen + sizeof(in_port_t);
	} break;
	default:
		socks5_sendrsp(ctx, SOCKS5RSP_ATYPNOSUPPORT);
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx,
			"SOCKS5: unsupported addrtype: %" PRIu8, addrtype);
		return -1;
	}
	if (len < expected) {
		return expected - len;
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
		FAIL();
		return -1;
	}

	/* protocol finished, remove header */
	if (!consume_rcvbuf(ctx, authlen + expected)) {
		return -1;
	}
	return 0;
}

static int socks5_auth(struct socks_ctx *restrict ctx)
{
	assert(ctx->state == STATE_HANDSHAKE1);
	const unsigned char *req = ctx->rbuf.data;
	const size_t len = ctx->rbuf.len;
	size_t want = sizeof(struct socks5_auth_req);
	if (len < want) {
		return want - len;
	}
	const uint8_t n =
		read_uint8(req + offsetof(struct socks5_auth_req, nmethods));
	want += n;
	if (len < want) {
		return want - len;
	}
	bool found = false;
	const uint8_t *methods = req + sizeof(struct socks5_auth_req);
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
	if (!send_rsp(ctx, wbuf, sizeof(wbuf))) {
		return -1;
	}
	if (!found) {
		LOGE("SOCKS5: no authentication method supported");
		return -1;
	}
	ctx->next = ctx->rbuf.data + sizeof(struct socks5_auth_req) + n;
	ctx->state = STATE_HANDSHAKE2;
	return socks5_req(ctx);
}

static int socks5_recv(struct socks_ctx *restrict ctx)
{
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
		return socks5_auth(ctx);
	case STATE_HANDSHAKE2:
		return socks5_req(ctx);
	default:
		break;
	}
	FAIL();
}

static int socks_dispatch(struct socks_ctx *restrict ctx)
{
	if (ctx->rbuf.len < 1) {
		return 1;
	}
	const uint8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		return socks4_recv(ctx);
	case SOCKS5:
		return socks5_recv(ctx);
	default:
		LOGE_F("unknown SOCKS version: %" PRIu8, version);
		break;
	}
	return -1;
}

static int socks_recv(struct socks_ctx *restrict ctx, const int fd)
{
	const ssize_t nrecv = recv(fd, ctx->rbuf.data, ctx->rbuf.cap, MSG_PEEK);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx, "recv: %s", strerror(err));
		return -1;
	} else if (nrecv == 0) {
		SOCKS_CTX_LOG(LOG_LEVEL_ERROR, ctx, "recv: early EOF");
		return -1;
	}
	ctx->rbuf.len = (size_t)nrecv;
	LOG_BIN_F(
		LOG_LEVEL_VERBOSE, ctx->rbuf.data, ctx->rbuf.len,
		"recv: fd=%d %zu bytes", fd, ctx->rbuf.len);
	const int want = socks_dispatch(ctx);
	if (want < 0) {
		return want;
	} else if (want == 0) {
		socket_rcvlowat(fd, 1);
		return 0;
	}
	if (ctx->rbuf.len + (size_t)want > ctx->rbuf.cap) {
		SOCKS_CTX_LOG(LOG_LEVEL_ERROR, ctx, "recv: header too long");
		return -1;
	}
	LOGV_F("socks_recv: fd=%d state=%d nrecv=%zd want=%d", fd, ctx->state,
	       nrecv, want);
	socket_rcvlowat(fd, (size_t)nrecv + (size_t)want);
	return 1;
}

static struct dialreq *make_dialreq(struct socks_ctx *restrict ctx)
{
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset == NULL) {
		struct dialreq *req = dialreq_new(&ctx->addr, 0);
		if (req == NULL) {
			LOGOOM();
			return NULL;
		}
		return req;
	}

	char request[FQDN_MAX_LENGTH + 1 + 5 + 1];
	(void)dialaddr_format(&ctx->addr, request, sizeof(request));
	switch (ctx->addr.type) {
	case ATYP_DOMAIN:
		return ruleset_resolve(ruleset, request);
	case ATYP_INET:
		return ruleset_route(ruleset, request);
	case ATYP_INET6:
		return ruleset_route6(ruleset, request);
	default:
		SOCKS_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx, "unsupported address type: %d",
			ctx->addr.type);
		break;
	}
	return NULL;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);

	struct socks_ctx *restrict ctx = watcher->data;
	const int ret = socks_recv(ctx, watcher->fd);
	if (ret < 0) {
		socks_ctx_stop(loop, ctx);
		socks_ctx_free(ctx);
		return;
	} else if (ret > 0) {
		ev_io_start(loop, watcher);
		return;
	}

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;

	struct dialreq *req = make_dialreq(ctx);
	if (req == NULL) {
		socks_sendrsp(ctx, false);
		socks_ctx_stop(loop, ctx);
		socks_ctx_free(ctx);
		return;
	}

	ctx->state = STATE_CONNECT;
	if (!dialer_start(&ctx->dialer, loop, req)) {
		socks_ctx_stop(loop, ctx);
		socks_ctx_free(ctx);
		return;
	}

	SOCKS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "connecting");
}

static struct socks_ctx *
socks_ctx_new(struct server *restrict s, const int accepted_fd)
{
	struct socks_ctx *restrict ctx = malloc(sizeof(struct socks_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->accepted_fd = accepted_fd;
	ctx->dialed_fd = -1;
	ctx->state = STATE_INIT;
	BUF_INIT(ctx->rbuf, sizeof(ctx->rbuf.data));

	const struct config *restrict conf = s->conf;

	struct ev_io *restrict w_read = &ctx->watcher;
	ev_io_init(w_read, recv_cb, accepted_fd, EV_READ);
	w_read->data = ctx;
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
	w_timeout->data = ctx;

	dialer_init(
		&ctx->dialer, conf,
		&(struct event_cb){
			.cb = dialer_cb,
			.ctx = ctx,
		});
	return ctx;
}

static void
socks_ctx_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	struct ev_io *restrict w_read = &ctx->watcher;
	ev_io_start(loop, w_read);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_start(loop, w_timeout);

	ctx->state = STATE_HANDSHAKE1;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen++;
}

void socks_serve(
	struct server *restrict s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct socks_ctx *restrict ctx = socks_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	socks_ctx_start(loop, ctx);
}
