/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"

#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "io/io.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum socks_state {
	STATE_INIT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_HANDSHAKE3,
	STATE_PROCESS,
	STATE_CONNECT,
	STATE_BIND, /* waiting for remote to connect to our listen socket */
	STATE_ESTABLISHED,
	STATE_BIDIRECTIONAL,
	STATE_UDP_RELAY, /* relaying UDP datagrams */
};

struct socks_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum socks_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct dialaddr addr;
	intmax_t accepted_ns;
	ev_timer w_timeout;
	union {
		/* state < STATE_CONNECTED */
		struct {
			ev_io w_socket;
			struct {
				uint_least8_t method;
				const char *username;
				const char *password;
			} auth;
			struct {
				BUFFER_HDR;
				unsigned char data[SOCKS_REQ_MAXLEN];
			} rbuf;
			unsigned char *next;
#if WITH_RULESET
			ev_idle w_process;
			struct ruleset_callback ruleset_callback;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		/* state >= STATE_CONNECTED */
		struct {
			struct transfer uplink, downlink;
		};
		/* state == STATE_UDP_RELAY */
		struct {
			/* watches dialed_fd UDP socket */
			ev_io w_udp;
			/* watches accepted_fd for TCP close */
			ev_io w_tcp;
			union sockaddr_max udp_peer;
			bool udp_peer_known;
			struct {
				BUFFER_HDR;
				unsigned char data[IO_BUFSIZE];
			} ubuf;
			/* fragment reassembly state */
			/* 0=idle, else next expected # */
			uint_least8_t frag_next;
			struct {
				BUFFER_HDR;
				unsigned char data[IO_BUFSIZE];
			} frag_buf;
			union sockaddr_max frag_target;
			socklen_t frag_target_len;
		};
	};
};
ASSERT_SUPER(struct gcbase, struct socks_ctx, gcbase);

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct socks_ctx *restrict ctx)
{
	char caddr[64];
	sa_format(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if (ctx->state != STATE_CONNECT && ctx->state != STATE_BIND) {
		return snprintf(
			s, maxlen, "[fd:%d] %s", ctx->accepted_fd, caddr);
	}
	char saddr[64];
	dialaddr_format(saddr, sizeof(saddr), &ctx->addr);
	return snprintf(
		s, maxlen, "[fd:%d] %s -> `%s'", ctx->accepted_fd, caddr,
		saddr);
}

#define SOCKS_CTX_LOG_F(level, ctx, format, ...)                               \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char status_str[256];                                          \
		const int nstatus =                                            \
			format_status(status_str, sizeof(status_str), (ctx));  \
		ASSERT(nstatus > 0);                                           \
		LOG_F(level, "%.*s: " format, nstatus, status_str,             \
		      __VA_ARGS__);                                            \
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
	case STATE_HANDSHAKE3:
		ev_io_stop(loop, &ctx->w_socket);
		stats->num_halfopen--;
		return;
	case STATE_PROCESS:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_process);
		if (ctx->ruleset_state != NULL) {
			ruleset_cancel(loop, ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
#endif
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_BIND:
		ev_io_stop(loop, &ctx->w_socket);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		break;
	case STATE_BIDIRECTIONAL:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	case STATE_UDP_RELAY:
		ev_io_stop(loop, &ctx->w_udp);
		ev_io_stop(loop, &ctx->w_tcp);
		stats->num_sessions--;
		break;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
	SOCKS_CTX_LOG_F(
		VERBOSE, ctx, "closed, %zu active", stats->num_sessions);
}

static void mark_ready(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	if (stats->num_sessions > stats->num_sessions_peak) {
		stats->num_sessions_peak = stats->num_sessions;
	}
	stats->num_success++;
	{
		const int_fast64_t elapsed =
			clock_monotonic_ns() - ctx->accepted_ns;
		stats->connect_ns
			[stats->num_connects % ARRAY_SIZE(stats->connect_ns)] =
			elapsed;
		stats->num_connects++;
	}
	SOCKS_CTX_LOG_F(
		DEBUG, ctx, "ready, %zu active sessions", stats->num_sessions);
}

static bool send_rsp(
	const struct socks_ctx *restrict ctx, const void *buf, const size_t len)
{
	const int fd = ctx->accepted_fd;
	LOG_BIN_F(
		VERYVERBOSE, buf, len, 0, "[fd:%d] send_rsp: %zu bytes", fd,
		len);
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			DEBUG, ctx, "send: (%d) %s", err, strerror(err));
		return false;
	}
	if ((size_t)nsend != len) {
		SOCKS_CTX_LOG_F(
			DEBUG, ctx, "send: %zu < %zu", (size_t)nsend, len);
		return false;
	}
	return true;
}

static bool
socks4_sendrsp(const struct socks_ctx *restrict ctx, const uint_fast8_t rsp)
{
	unsigned char buf[SOCKS4_HDR_LEN];
	const struct socks4_hdr h = { .version = 0, .command = rsp };
	socks4hdr_write(buf, &h);
	return send_rsp(ctx, buf, SOCKS4_HDR_LEN);
}

static bool
socks5_sendrsp(const struct socks_ctx *restrict ctx, const uint_fast8_t rsp)
{
	union sockaddr_max addr = {
		.sa.sa_family = AF_INET,
	};
	socklen_t addrlen = sizeof(addr);
	if (ctx->dialed_fd != -1) {
		if (getsockname(ctx->dialed_fd, &addr.sa, &addrlen) != 0) {
			const int err = errno;
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "getsockname: (%d) %s", err,
				strerror(err));
		}
	}
	unsigned char buf[SOCKS5_RSP_MAXLEN];
	struct socks5_hdr h = { .version = SOCKS5,
				.command = rsp,
				.reserved = 0 };
	size_t len = SOCKS5_HDR_LEN;
	unsigned char *const restrict addrbuf = buf + len;
	switch (addr.sa.sa_family) {
	case AF_INET: {
		h.addrtype = SOCKS5ADDR_IPV4;
		memcpy(addrbuf, &addr.in.sin_addr, sizeof(addr.in.sin_addr));
		len += sizeof(addr.in.sin_addr);
		unsigned char *const restrict portbuf = buf + len;
		memcpy(portbuf, &addr.in.sin_port, sizeof(addr.in.sin_port));
		len += sizeof(addr.in.sin_port);
	} break;
	case AF_INET6: {
		h.addrtype = SOCKS5ADDR_IPV6;
		memcpy(addrbuf, &addr.in6.sin6_addr,
		       sizeof(addr.in6.sin6_addr));
		len += sizeof(addr.in6.sin6_addr);
		unsigned char *const restrict portbuf = buf + len;
		memcpy(portbuf, &addr.in6.sin6_port,
		       sizeof(addr.in6.sin6_port));
		len += sizeof(addr.in6.sin6_port);
	} break;
	default:
		FAILMSGF("unexpected address family: %d", addr.sa.sa_family);
	}
	socks5hdr_write(buf, &h);
	return send_rsp(ctx, buf, len);
}

static bool socks_sendrsp(struct socks_ctx *restrict ctx, const bool ok)
{
	const uint_fast8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		return socks4_sendrsp(
			ctx, ok ? SOCKS4RSP_GRANTED : SOCKS4RSP_REJECTED);
	case SOCKS5:
		return socks5_sendrsp(
			ctx, ok ? SOCKS5RSP_SUCCEEDED : SOCKS5RSP_FAIL);
	default:
		break;
	}
	FAILMSGF("unexpected socks version: %d", version);
}

static uint_fast8_t socks5_err2rsp(const int err)
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

static uint_fast8_t
socks5_dialerr2rsp(const enum dialer_error err, const int syserr)
{
	switch (err) {
	case DIALER_OK:
		return SOCKS5RSP_SUCCEEDED;
	case DIALER_ERR_SYSTEM:
		return socks5_err2rsp(syserr);
	case DIALER_ERR_RESOLVE:
		return SOCKS5RSP_HOSTUNREACH;
	case DIALER_ERR_CONNECT:
		return socks5_err2rsp(syserr);
	case DIALER_ERR_PROXY_AUTH:
	case DIALER_ERR_PROXY_REJECT:
		return SOCKS5RSP_NOALLOWED;
	case DIALER_ERR_PROXY_REFUSED:
		return SOCKS5RSP_CONNREFUSED;
	case DIALER_ERR_BLOCKED:
		return SOCKS5RSP_NOALLOWED;
	default:
		break;
	}
	return SOCKS5RSP_FAIL;
}

static void socks_senderr(
	const struct socks_ctx *restrict ctx, const enum dialer_error err,
	const int syserr)
{
	const uint_fast8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		break;
	case SOCKS5:
		socks5_sendrsp(ctx, socks5_dialerr2rsp(err, syserr));
		break;
	default:
		FAILMSGF("unexpected socks version: %d", version);
	}
}

static void xfer_state_cb(struct ev_loop *restrict loop, void *data)
{
	struct socks_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_ESTABLISHED ||
	       ctx->state == STATE_BIDIRECTIONAL);

	if (ctx->uplink.state == XFER_FINISHED &&
	    ctx->downlink.state == XFER_FINISHED) {
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ctx->state == STATE_ESTABLISHED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		mark_ready(loop, ctx);
		return;
	}
}

static void
socks_start_transfer(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	if (ctx->s->conf->bidir_timeout) {
		ctx->state = STATE_ESTABLISHED;
	} else {
		mark_ready(loop, ctx);
	}
	const struct transfer_state_cb cb = {
		.func = xfer_state_cb,
		.data = ctx,
	};
	struct server_stats *restrict stats = &ctx->s->stats;
	transfer_init(
		&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up, true, ctx->s->conf->pipe);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down, false, ctx->s->conf->pipe);
	SOCKS_CTX_LOG_F(
		DEBUG, ctx,
		"transfer start: uplink [%d->%d], downlink [%d->%d]",
		ctx->accepted_fd, ctx->dialed_fd, ctx->dialed_fd,
		ctx->accepted_fd);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static int socks4a_req(struct socks_ctx *restrict ctx)
{
	const char *restrict name = (const char *)ctx->next;
	const size_t maxlen = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	const size_t namelen = strnlen(name, maxlen);
	if (namelen > FQDN_MAX_LENGTH) {
		return -1;
	}
	if (namelen == maxlen) {
		return 1;
	}

	ctx->addr.type = ATYP_DOMAIN;
	struct domain_name *restrict domain = &ctx->addr.domain;
	domain->len = (uint_least8_t)namelen;
	memcpy(domain->name, name, namelen);

	/* protocol finished */
	return 0;
}

static int socks4_req(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE1);
	ASSERT(ctx->next == ctx->rbuf.data);
	const unsigned char *restrict hdr = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	const size_t want = SOCKS4_HDR_LEN + 1;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks4_hdr h;
	socks4hdr_read(&h, hdr);
	const uint_fast8_t command = h.command;
	if (command != SOCKS4CMD_CONNECT) {
		SOCKS_CTX_LOG_F(
			WARNING, ctx,
			"SOCKS4 command not supported: %" PRIuFAST8, command);
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return -1;
	}
	const char *userid = (const char *)hdr + SOCKS4_HDR_LEN;
	const size_t maxlen = ctx->rbuf.len - SOCKS4_HDR_LEN;
	const size_t idlen = strnlen(userid, maxlen);
	if (idlen >= 256) {
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return -1;
	}
	if (idlen == maxlen) {
		return 1;
	}
	ctx->auth.username = userid;
	ctx->auth.password = NULL;
	ctx->addr.port = h.port;

	const uint_fast32_t ip = h.address;
	const uint_fast32_t mask = UINT32_C(0xFFFFFF00);
	if (!(ip & mask) && (ip & ~mask)) {
		/* SOCKS 4A */
		ctx->next += SOCKS4_HDR_LEN + idlen + 1;
		return socks4a_req(ctx);
	}

	ctx->addr.type = ATYP_INET;
	write_uint32(&ctx->addr.in, h.address);

	/* protocol finished */
	return 0;
}

static int socks5_req(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE3);
	const unsigned char *restrict hdr = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = SOCKS5_HDR_LEN;
	if (len < want) {
		return (int)(want - len);
	}

	struct socks5_hdr h;
	socks5hdr_read(&h, hdr);
	const uint_fast8_t version = h.version;
	if (version != SOCKS5) {
		SOCKS_CTX_LOG_F(
			WARNING, ctx, "SOCKS5: unsupported version %" PRIuFAST8,
			version);
		return -1;
	}
	const uint_fast8_t command = h.command;
	switch (command) {
	case SOCKS5CMD_CONNECT:
		break;
	case SOCKS5CMD_BIND:
		if (!ctx->s->conf->socks5_bind) {
			socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
			SOCKS_CTX_LOG_F(
				WARNING, ctx,
				"SOCKS5 BIND not allowed, command=%" PRIuFAST8,
				command);
			return -1;
		}
		break;
	case SOCKS5CMD_UDPASSOCIATE:
		if (!ctx->s->conf->socks5_udp) {
			socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
			SOCKS_CTX_LOG_F(
				WARNING, ctx,
				"SOCKS5 UDP ASSOCIATE not allowed, command=%" PRIuFAST8,
				command);
			return -1;
		}
		break;
	default:
		socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
		SOCKS_CTX_LOG_F(
			WARNING, ctx, "SOCKS5: unsupported command %" PRIuFAST8,
			command);
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
		want += 1;
		if (len < want) {
			return (int)(want - len);
		}
		const uint_fast8_t addrlen = read_uint8(hdr + SOCKS5_HDR_LEN);
		want += (size_t)addrlen + sizeof(in_port_t);
	} break;
	default:
		socks5_sendrsp(ctx, SOCKS5RSP_ATYPNOSUPPORT);
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "SOCKS5: unsupported addrtype: %" PRIuFAST8,
			addrtype);
		return -1;
	}
	if (len < want) {
		return (int)(want - len);
	}
	const unsigned char *restrict rawaddr = hdr + SOCKS5_HDR_LEN;
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
		const uint_fast8_t addrlen = read_uint8(rawaddr);
		rawaddr++;
		ctx->addr.type = ATYP_DOMAIN;
		struct domain_name *restrict domain = &ctx->addr.domain;
		domain->len = addrlen;
		memcpy(domain->name, rawaddr, addrlen);
		ctx->addr.port = read_uint16(rawaddr + addrlen);
	} break;
	default:
		FAILMSGF("unexpected socks5 address type: %d", addrtype);
	}

	/* protocol finished */
	return 0;
}

static int socks5_auth(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE2);
	switch (ctx->auth.method) {
	case SOCKS5AUTH_NOAUTH:
		ctx->state = STATE_HANDSHAKE3;
		return socks5_req(ctx);
	case SOCKS5AUTH_USERPASS:
		break;
	default:
		FAILMSGF("unexpected socks5 auth method: %d", ctx->auth.method);
	}
	const unsigned char *restrict req = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = 2;
	if (len < want) {
		return (int)(want - len);
	}
	const uint_fast8_t ver = read_uint8(req + 0);
	if (ver != 0x01) {
		SOCKS_CTX_LOG(
			ERROR, ctx,
			"SOCKS5: incompatible authentication version");
		return -1;
	}
	const uint_fast8_t ulen = read_uint8(req + 1);
	want += ulen + 1;
	if (len < want) {
		return (int)(want - len);
	}
	const uint_fast8_t plen = read_uint8(req + 2 + ulen);
	want += plen;
	if (len < want) {
		return (int)(want - len);
	}
	unsigned char wbuf[2] = {
		0x01, /* VER = 1 */
		0x01, /* STATUS = FAILED */
	};
	if (ulen == 0 || plen == 0) {
		(void)send_rsp(ctx, wbuf, sizeof(wbuf));
		return -1;
	}
	/* rewrite the buffer as null-terminated string */
	const char *req_user = (const char *)req + 2;
	char *username = (char *)ctx->next;
	for (size_t i = 0; i < ulen; i++) {
		username[i] = req_user[i];
	}
	username[ulen] = '\0';
	const char *req_pass = (const char *)req + 2 + ulen + 1;
	char *password = username + ulen + 1;
	for (size_t i = 0; i < plen; i++) {
		password[i] = req_pass[i];
	}
	password[plen] = '\0';
	ctx->auth.username = username;
	ctx->auth.password = password;

	/* authentication is always successful because the request is unknown yet */
	wbuf[1] = 0x00; /* STATUS = SUCCESS */
	if (!send_rsp(ctx, wbuf, sizeof(wbuf))) {
		return -1;
	}

	ctx->next += want;
	ctx->state = STATE_HANDSHAKE3;
	return socks5_req(ctx);
}

static int socks5_authmethod(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE1);
	const unsigned char *restrict req = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = SOCKS5_AUTH_REQ_FIXED_LEN;
	if (len < want) {
		return (int)(want - len);
	}
	struct socks5_auth_req ah;
	socks5authreq_read(&ah, req);
	const uint_fast8_t n = ah.nmethods;
	want += n;
	if (len < want) {
		return (int)(want - len);
	}
	const bool auth_required = ctx->s->conf->auth_required;
	uint_fast8_t method = SOCKS5AUTH_NOACCEPTABLE;
	const unsigned char *restrict methods = req + SOCKS5_AUTH_REQ_FIXED_LEN;
	for (size_t i = 0; i < n; i++) {
		switch (methods[i]) {
		case SOCKS5AUTH_NOAUTH:
			if (!auth_required) {
				break;
			}
			continue;
		case SOCKS5AUTH_USERPASS:
			break;
		default:
			continue;
		}
		method = methods[i];
		break;
	}
	unsigned char wbuf[SOCKS5_AUTH_RSP_LEN];
	const struct socks5_auth_rsp ar = { .version = SOCKS5,
					    .method = method };
	socks5authrsp_write(wbuf, &ar);
	if (!send_rsp(ctx, wbuf, SOCKS5_AUTH_RSP_LEN)) {
		return -1;
	}
	if (method == SOCKS5AUTH_NOACCEPTABLE) {
		SOCKS_CTX_LOG(
			ERROR, ctx,
			"SOCKS5: no acceptable authentication method");
		return -1;
	}
	ctx->auth.method = method;

	ctx->next += want;
	ctx->state = STATE_HANDSHAKE2;
	return socks5_auth(ctx);
}

static int socks_dispatch(struct socks_ctx *restrict ctx)
{
	if (ctx->rbuf.len < 1) {
		return 1;
	}
	const int version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		return socks4_req(ctx);
	case SOCKS5:
		switch (ctx->state) {
		case STATE_HANDSHAKE1:
			return socks5_authmethod(ctx);
		case STATE_HANDSHAKE2:
			return socks5_auth(ctx);
		case STATE_HANDSHAKE3:
			return socks5_req(ctx);
		default:
			break;
		}
		FAILMSGF("unexpected socks5 state: %d", ctx->state);
	default:
		break;
	}
	SOCKS_CTX_LOG_F(
		ERROR, ctx, "invalid SOCKS message: version=0x%02x", version);
	return -1;
}

static int socks_recv(struct socks_ctx *restrict ctx, const int fd)
{
	unsigned char *buf = ctx->rbuf.data + ctx->rbuf.len;
	const size_t n = ctx->rbuf.cap - ctx->rbuf.len;
	const ssize_t nrecv = recv(fd, buf, n, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		SOCKS_CTX_LOG_F(
			DEBUG, ctx, "recv: (%d) %s", err, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		/* connection is not established yet, we do not expect EOF here */
		SOCKS_CTX_LOG(DEBUG, ctx, "recv: early EOF");
		return -1;
	}
	ctx->rbuf.len += (size_t)nrecv;
	LOG_BIN_F(
		VERYVERBOSE, ctx->rbuf.data, ctx->rbuf.len, 0,
		"[fd:%d] recv: %zu bytes", fd, ctx->rbuf.len);
	const int want = socks_dispatch(ctx);
	if (want < 0) {
		return want;
	}
	if (want == 0) {
		return 0;
	}
	if (ctx->rbuf.len + (size_t)want > ctx->rbuf.cap) {
		SOCKS_CTX_LOG(ERROR, ctx, "garbage after socks header");
		return -1;
	}
	return 1;
}

static void socks_connect(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	if (ctx->dialreq == NULL) {
		(void)socks_sendrsp(ctx, false);
		gc_unref(&ctx->gcbase);
		return;
	}

	SOCKS_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(
		&ctx->dialer, loop, ctx->dialreq, ctx->s->conf,
		ctx->s->resolver);
}

static bool socks5_sendrsp_addr(
	const struct socks_ctx *restrict ctx, const uint_fast8_t rsp,
	const union sockaddr_max *restrict addr)
{
	unsigned char buf[SOCKS5_RSP_MAXLEN];
	struct socks5_hdr h = { .version = SOCKS5,
				.command = rsp,
				.reserved = 0 };
	size_t len = SOCKS5_HDR_LEN;
	unsigned char *const restrict addrbuf = buf + len;
	switch (addr->sa.sa_family) {
	case AF_INET: {
		h.addrtype = SOCKS5ADDR_IPV4;
		memcpy(addrbuf, &addr->in.sin_addr, sizeof(addr->in.sin_addr));
		len += sizeof(addr->in.sin_addr);
		memcpy(buf + len, &addr->in.sin_port,
		       sizeof(addr->in.sin_port));
		len += sizeof(addr->in.sin_port);
	} break;
	case AF_INET6: {
		h.addrtype = SOCKS5ADDR_IPV6;
		memcpy(addrbuf, &addr->in6.sin6_addr,
		       sizeof(addr->in6.sin6_addr));
		len += sizeof(addr->in6.sin6_addr);
		memcpy(buf + len, &addr->in6.sin6_port,
		       sizeof(addr->in6.sin6_port));
		len += sizeof(addr->in6.sin6_port);
	} break;
	default:
		FAILMSGF("unexpected address family: %d", addr->sa.sa_family);
	}
	socks5hdr_write(buf, &h);
	return send_rsp(ctx, buf, len);
}

static bool bind_peer_matches_request(
	const struct socks_ctx *restrict ctx,
	const union sockaddr_max *restrict peer_sa)
{
	const uint_least16_t req_port = ctx->addr.port;
	switch (ctx->addr.type) {
	case ATYP_INET: {
		struct sockaddr_in in = {
			.sin_family = AF_INET,
			.sin_port = htons(req_port),
			.sin_addr = ctx->addr.in,
		};
		return sa_matches((struct sockaddr *)&in, &peer_sa->sa);
	}
	case ATYP_INET6: {
		struct sockaddr_in6 in6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(req_port),
			.sin6_addr = ctx->addr.in6,
		};
		return sa_matches((struct sockaddr *)&in6, &peer_sa->sa);
	}
	case ATYP_DOMAIN:
		if (req_port == 0) {
			return true;
		}
		switch (peer_sa->sa.sa_family) {
		case AF_INET:
			return peer_sa->in.sin_port == htons(req_port);
		case AF_INET6:
			return peer_sa->in6.sin6_port == htons(req_port);
		default:
			return false;
		}
	default:
		break;
	}
	FAILMSGF("unexpected address type: %d", ctx->addr.type);
}

static void
bind_accept_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_BIND);

	union sockaddr_max peer_sa;
	socklen_t peer_len = sizeof(peer_sa);
	const int conn_fd = accept(ctx->dialed_fd, &peer_sa.sa, &peer_len);
	if (conn_fd < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "accept: (%d) %s", err, strerror(err));
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	SOCKS_CTX_LOG_F(VERBOSE, ctx, "BIND: accepted [fd:%d]", conn_fd);
	if (!bind_peer_matches_request(ctx, &peer_sa)) {
		char peer_str[64];
		sa_format(peer_str, sizeof(peer_str), &peer_sa.sa);
		char expect_str[64];
		dialaddr_format(expect_str, sizeof(expect_str), &ctx->addr);
		SOCKS_CTX_LOG_F(
			WARNING, ctx,
			"BIND peer mismatch (expected `%s', got `%s'), allowing",
			expect_str, peer_str);
	}
	if (!socket_set_nonblock(conn_fd)) {
		CLOSE_FD(conn_fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	ev_io_stop(loop, &ctx->w_socket);
	CLOSE_FD(ctx->dialed_fd);
	ctx->dialed_fd = conn_fd;
	if (!socks5_sendrsp_addr(ctx, SOCKS5RSP_SUCCEEDED, &peer_sa)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	dialreq_free(ctx->dialreq);
	socks_start_transfer(loop, ctx);
}

static void
socks_bind_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_PROCESS);
	const int family = ctx->accepted_sa.sa.sa_family;
	const int listen_fd = socket(family, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "socket: (%d) %s", err, strerror(err));
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	{
		union sockaddr_max bindsa;
		socklen_t bindlen;
		memset(&bindsa, 0, sizeof(bindsa));
		if (family == AF_INET6) {
			bindsa.in6.sin6_family = AF_INET6;
			bindsa.in6.sin6_addr = in6addr_any;
			bindsa.in6.sin6_port = 0;
			bindlen = sizeof(struct sockaddr_in6);
		} else {
			bindsa.in.sin_family = AF_INET;
			bindsa.in.sin_addr.s_addr = htonl(INADDR_ANY);
			bindsa.in.sin_port = 0;
			bindlen = sizeof(struct sockaddr_in);
		}
		if (bind(listen_fd, &bindsa.sa, bindlen) != 0) {
			const int err = errno;
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "bind: (%d) %s", err,
				strerror(err));
			CLOSE_FD(listen_fd);
			socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
			gc_unref(&ctx->gcbase);
			return;
		}
	}
	if (listen(listen_fd, 1) != 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "listen: (%d) %s", err, strerror(err));
		CLOSE_FD(listen_fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	if (!socket_set_nonblock(listen_fd)) {
		CLOSE_FD(listen_fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	ctx->dialed_fd = listen_fd;
	if (!socks5_sendrsp(ctx, SOCKS5RSP_SUCCEEDED)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	SOCKS_CTX_LOG(VERBOSE, ctx, "BIND: listening");
	ctx->state = STATE_BIND;
	ev_io_init(&ctx->w_socket, bind_accept_cb, listen_fd, EV_READ);
	ctx->w_socket.data = ctx;
	ev_io_start(loop, &ctx->w_socket);
}

/* Returns the total UDP header length for the given datagram buffer, or -1 if
 * the buffer is too short or the address type is unsupported. */
static int udp_hdr_len(const unsigned char *restrict buf, const size_t buflen)
{
	if (buflen < SOCKS5_UDP_HDR_LEN) {
		return -1;
	}
	struct socks5_udp_hdr h;
	socks5udphdr_read(&h, buf);
	switch (h.addrtype) {
	case SOCKS5ADDR_IPV4:
		return buflen >= SOCKS5_UDP_HDR_IPV4LEN ?
			       (int)SOCKS5_UDP_HDR_IPV4LEN :
			       -1;
	case SOCKS5ADDR_IPV6:
		return buflen >= SOCKS5_UDP_HDR_IPV6LEN ?
			       (int)SOCKS5_UDP_HDR_IPV6LEN :
			       -1;
	default:
		return -1;
	}
}

/* Parses the SOCKS5 UDP header address and port from buf into *sa / *salen,
 * and writes the total header length into *hdr_len_out.
 * Returns false if the buffer is too short or the address type is unsupported.
 */
static bool udp_parse_addr(
	const unsigned char *restrict buf, const size_t buflen,
	union sockaddr_max *restrict sa, socklen_t *restrict salen,
	size_t *restrict hdr_len_out)
{
	memset(sa, 0, sizeof(*sa));
	struct socks5_udp_hdr h;
	socks5udphdr_read(&h, buf);
	switch (h.addrtype) {
	case SOCKS5ADDR_IPV4:
		if (buflen < SOCKS5_UDP_HDR_IPV4LEN) {
			return false;
		}
		sa->in.sin_family = AF_INET;
		memcpy(&sa->in.sin_addr, buf + SOCKS5_UDP_HDR_LEN,
		       sizeof(sa->in.sin_addr));
		memcpy(&sa->in.sin_port,
		       buf + SOCKS5_UDP_HDR_LEN + sizeof(struct in_addr),
		       sizeof(sa->in.sin_port));
		*salen = sizeof(struct sockaddr_in);
		*hdr_len_out = SOCKS5_UDP_HDR_IPV4LEN;
		return true;
	case SOCKS5ADDR_IPV6:
		if (buflen < SOCKS5_UDP_HDR_IPV6LEN) {
			return false;
		}
		sa->in6.sin6_family = AF_INET6;
		memcpy(&sa->in6.sin6_addr, buf + SOCKS5_UDP_HDR_LEN,
		       sizeof(sa->in6.sin6_addr));
		memcpy(&sa->in6.sin6_port,
		       buf + SOCKS5_UDP_HDR_LEN + sizeof(struct in6_addr),
		       sizeof(sa->in6.sin6_port));
		*salen = sizeof(struct sockaddr_in6);
		*hdr_len_out = SOCKS5_UDP_HDR_IPV6LEN;
		return true;
	default:
		return false;
	}
}

static void udp_frag_reset(struct socks_ctx *restrict ctx)
{
	ctx->frag_next = 0;
	BUF_INIT(ctx->frag_buf, 0);
}

static void udp_frag_flush(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	const ssize_t nsend =
		sendto(ctx->dialed_fd, ctx->frag_buf.data, ctx->frag_buf.len, 0,
		       &ctx->frag_target.sa, ctx->frag_target_len);
	if (nsend < 0) {
		const int err = errno;
		if (!IS_TRANSIENT_ERROR(err)) {
			SOCKS_CTX_LOG_F(
				ERROR, ctx,
				"sendto target (reassembled): (%d) %s", err,
				strerror(err));
		}
	}
	udp_frag_reset(ctx);
	UNUSED(loop);
}

/* Handles a fragmented UDP datagram from the client (frag != 0).
 * Assembles fragments into frag_buf and forwards the reassembled payload once
 * the last fragment arrives. Out-of-order or overflowing sequences are
 * discarded. */
static void udp_frag_client_recv(
	struct ev_loop *loop, struct socks_ctx *restrict ctx,
	const size_t nrecv, const uint_fast8_t frag)
{
	const uint_fast8_t pos = frag & UINT8_C(0x7F);
	const bool is_last = (frag & SOCKS5_UDP_FRAG_LAST) != 0;
	const unsigned char *const buf = ctx->ubuf.data;

	if (pos == 1) {
		/* First fragment: save target address and start accumulation */
		if (ctx->frag_next != 0) {
			SOCKS_CTX_LOG(
				WARNING, ctx,
				"UDP frag: new sequence discards in-progress one");
		}
		size_t hdr_len;
		if (!udp_parse_addr(
			    buf, nrecv, &ctx->frag_target,
			    &ctx->frag_target_len, &hdr_len)) {
			return;
		}
		const size_t payload_len = nrecv - hdr_len;
		if (payload_len > IO_BUFSIZE) {
			SOCKS_CTX_LOG(
				WARNING, ctx,
				"UDP frag: first fragment too large, discarding");
			return;
		}
		BUF_INIT(ctx->frag_buf, 0);
		memcpy(ctx->frag_buf.data, buf + hdr_len, payload_len);
		ctx->frag_buf.len = payload_len;
		if (is_last) {
			udp_frag_flush(loop, ctx);
			return;
		}
		ctx->frag_next = 2;
		return;
	}

	if (pos == 0 || pos != ctx->frag_next) {
		if (ctx->frag_next != 0) {
			SOCKS_CTX_LOG(
				WARNING, ctx,
				"UDP frag: out-of-order, discarding sequence");
			udp_frag_reset(ctx);
		} else {
			SOCKS_CTX_LOG(
				WARNING, ctx,
				"UDP frag: unexpected fragment, discarding");
		}
		return;
	}

	/* Subsequent in-order fragment: target address repeats but we use the
	 * one saved from fragment 1 */
	const int hl = udp_hdr_len(buf, nrecv);
	if (hl < 0) {
		SOCKS_CTX_LOG(
			WARNING, ctx,
			"UDP frag: malformed fragment, discarding sequence");
		udp_frag_reset(ctx);
		return;
	}
	const size_t hdr_len = (size_t)hl;
	const size_t payload_len = nrecv - hdr_len;
	if (payload_len > IO_BUFSIZE - ctx->frag_buf.len) {
		SOCKS_CTX_LOG(
			WARNING, ctx,
			"UDP frag: reassembly overflow, discarding sequence");
		udp_frag_reset(ctx);
		return;
	}
	memcpy(ctx->frag_buf.data + ctx->frag_buf.len, buf + hdr_len,
	       payload_len);
	ctx->frag_buf.len += payload_len;
	if (is_last) {
		udp_frag_flush(loop, ctx);
		return;
	}
	ctx->frag_next++;
}

static void
udp_relay_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);

	union sockaddr_max from_sa;
	socklen_t from_len = sizeof(from_sa);
	const ssize_t nrecv = recvfrom(
		ctx->dialed_fd, ctx->ubuf.data, IO_BUFSIZE, 0, &from_sa.sa,
		&from_len);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "recvfrom: (%d) %s", err, strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (!ctx->udp_peer_known || sa_equals(&from_sa.sa, &ctx->udp_peer.sa)) {
		/* Client -> target: strip SOCKS5 UDP header and forward */
		if (!ctx->udp_peer_known) {
			sa_copy(&ctx->udp_peer.sa, &from_sa.sa);
			ctx->udp_peer_known = true;
		}
		if ((size_t)nrecv < SOCKS5_UDP_HDR_LEN) {
			return; /* too short, discard */
		}
		struct socks5_udp_hdr udph;
		socks5udphdr_read(&udph, ctx->ubuf.data);
		const uint_fast8_t frag = udph.frag;
		if (frag != 0) {
			udp_frag_client_recv(loop, ctx, (size_t)nrecv, frag);
			return;
		}
		/* Non-fragmented datagram: parse target and forward payload */
		union sockaddr_max target_sa;
		socklen_t target_len;
		size_t hdr_len;
		if (!udp_parse_addr(
			    ctx->ubuf.data, (size_t)nrecv, &target_sa,
			    &target_len, &hdr_len)) {
			return; /* unsupported address type, discard */
		}
		const ssize_t nsend =
			sendto(ctx->dialed_fd, ctx->ubuf.data + hdr_len,
			       (size_t)nrecv - hdr_len, 0, &target_sa.sa,
			       target_len);
		if (nsend < 0) {
			const int err = errno;
			if (!IS_TRANSIENT_ERROR(err)) {
				SOCKS_CTX_LOG_F(
					ERROR, ctx, "sendto target: (%d) %s",
					err, strerror(err));
			}
		}
	} else {
		/* Target -> client: prepend SOCKS5 UDP header and send */
		unsigned char hdr_buf[SOCKS5_UDP_HDR_MAXLEN];
		size_t hdr_len;
		struct socks5_udp_hdr udph = { .reserved = { 0, 0 },
					       .frag = 0 };
		switch (from_sa.sa.sa_family) {
		case AF_INET:
			udph.addrtype = SOCKS5ADDR_IPV4;
			memcpy(hdr_buf + SOCKS5_UDP_HDR_LEN,
			       &from_sa.in.sin_addr,
			       sizeof(from_sa.in.sin_addr));
			hdr_len = SOCKS5_UDP_HDR_LEN +
				  sizeof(from_sa.in.sin_addr);
			memcpy(hdr_buf + hdr_len, &from_sa.in.sin_port,
			       sizeof(from_sa.in.sin_port));
			hdr_len += sizeof(from_sa.in.sin_port);
			break;
		case AF_INET6:
			udph.addrtype = SOCKS5ADDR_IPV6;
			memcpy(hdr_buf + SOCKS5_UDP_HDR_LEN,
			       &from_sa.in6.sin6_addr,
			       sizeof(from_sa.in6.sin6_addr));
			hdr_len = SOCKS5_UDP_HDR_LEN +
				  sizeof(from_sa.in6.sin6_addr);
			memcpy(hdr_buf + hdr_len, &from_sa.in6.sin6_port,
			       sizeof(from_sa.in6.sin6_port));
			hdr_len += sizeof(from_sa.in6.sin6_port);
			break;
		default:
			return; /* unexpected address family, discard */
		}
		socks5udphdr_write(hdr_buf, &udph);
		const struct iovec iov[2] = {
			{ .iov_base = hdr_buf, .iov_len = hdr_len },
			{ .iov_base = ctx->ubuf.data,
			  .iov_len = (size_t)nrecv },
		};
		const struct msghdr msg = {
			.msg_name = &ctx->udp_peer.sa,
			.msg_namelen = sa_len(&ctx->udp_peer.sa),
			.msg_iov = (struct iovec *)iov,
			.msg_iovlen = 2,
		};
		const ssize_t nsend = sendmsg(ctx->dialed_fd, &msg, 0);
		if (nsend < 0) {
			const int err = errno;
			if (!IS_TRANSIENT_ERROR(err)) {
				SOCKS_CTX_LOG_F(
					ERROR, ctx,
					"sendmsg to client: (%d) %s", err,
					strerror(err));
			}
		}
	}
	UNUSED(loop);
}

static void
tcp_monitor_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);
	/* Any readable event: check for EOF on the TCP control connection */
	unsigned char discard_buf[64];
	const ssize_t n =
		recv(ctx->accepted_fd, discard_buf, sizeof(discard_buf), 0);
	if (n < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "TCP control: recv: (%d) %s", err,
			strerror(err));
	} else if (n > 0) {
		/* Unexpected data on TCP control connection; ignore */
		return;
	}
	SOCKS_CTX_LOG(VERBOSE, ctx, "UDP ASSOCIATE: TCP control closed");
	gc_unref(&ctx->gcbase);
	UNUSED(loop);
}

static void
socks_udp_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_PROCESS);
	const int family = ctx->accepted_sa.sa.sa_family;
	const int udp_fd = socket(family, SOCK_DGRAM, 0);
	if (udp_fd < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "socket: (%d) %s", err, strerror(err));
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	{
		union sockaddr_max bindsa;
		socklen_t bindlen;
		memset(&bindsa, 0, sizeof(bindsa));
		if (family == AF_INET6) {
			bindsa.in6.sin6_family = AF_INET6;
			bindsa.in6.sin6_addr = in6addr_any;
			bindsa.in6.sin6_port = 0;
			bindlen = sizeof(struct sockaddr_in6);
		} else {
			bindsa.in.sin_family = AF_INET;
			bindsa.in.sin_addr.s_addr = htonl(INADDR_ANY);
			bindsa.in.sin_port = 0;
			bindlen = sizeof(struct sockaddr_in);
		}
		if (bind(udp_fd, &bindsa.sa, bindlen) != 0) {
			const int err = errno;
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "bind: (%d) %s", err,
				strerror(err));
			CLOSE_FD(udp_fd);
			socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
			gc_unref(&ctx->gcbase);
			return;
		}
	}
	if (!socket_set_nonblock(udp_fd)) {
		CLOSE_FD(udp_fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	ctx->dialed_fd = udp_fd;
	if (!socks5_sendrsp(ctx, SOCKS5RSP_SUCCEEDED)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	SOCKS_CTX_LOG(VERBOSE, ctx, "UDP ASSOCIATE: relay ready");
	struct server_stats *restrict stats = &ctx->s->stats;
	ev_timer_stop(loop, &ctx->w_timeout);
	stats->num_halfopen--;
	stats->num_sessions++;
	if (stats->num_sessions > stats->num_sessions_peak) {
		stats->num_sessions_peak = stats->num_sessions;
	}
	stats->num_success++;
	ctx->udp_peer_known = false;
	udp_frag_reset(ctx);
	ctx->state = STATE_UDP_RELAY;
	ev_io_init(&ctx->w_udp, udp_relay_cb, udp_fd, EV_READ);
	ctx->w_udp.data = ctx;
	ev_io_start(loop, &ctx->w_udp);
	ev_io_init(&ctx->w_tcp, tcp_monitor_cb, ctx->accepted_fd, EV_READ);
	ctx->w_tcp.data = ctx;
	ev_io_start(loop, &ctx->w_tcp);
	SOCKS_CTX_LOG_F(
		VERBOSE, ctx, "UDP ASSOCIATE: %zu active sessions",
		stats->num_sessions);
}

static struct dialreq *make_dialreq(
	struct socks_ctx *restrict ctx, const struct dialaddr *restrict addr)
{
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	dialaddr_copy(&req->addr, addr);
	return req;
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;

	const int ret = socks_recv(ctx, watcher->fd);
	if (ret < 0) {
		/* error */
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ret > 0) {
		/* want more data */
		return;
	}

	/* ignore further io events */
	ctx->state = STATE_PROCESS;
	ev_io_stop(loop, watcher);
	{
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
	}

#if WITH_RULESET
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		/* BIND and UDP ASSOCIATE are not supported with a ruleset.
		 * All commands are routed uniformly through the ruleset and
		 * then dialed as TCP CONNECT; the special-case dispatch below
		 * is intentionally skipped. */
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif
	/* Dispatch SOCKS5 BIND and UDP ASSOCIATE before dialing */
	if (read_uint8(ctx->rbuf.data) == SOCKS5) {
		struct socks5_hdr h;
		socks5hdr_read(&h, ctx->next);
		if (h.command == SOCKS5CMD_BIND) {
			socks_bind_start(loop, ctx);
			return;
		}
		if (h.command == SOCKS5CMD_UDPASSOCIATE) {
			socks_udp_start(loop, ctx);
			return;
		}
	}
	ctx->dialreq = make_dialreq(ctx, &ctx->addr);
	socks_connect(loop, ctx);
}

static void
timeout_cb(struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);

	struct socks_ctx *restrict ctx = watcher->data;
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
	case STATE_HANDSHAKE3:
		SOCKS_CTX_LOG(WARNING, ctx, "handshake timeout");
		break;
	case STATE_PROCESS:
	case STATE_CONNECT:
	case STATE_BIND: {
		const uint_fast8_t version = read_uint8(ctx->rbuf.data);
		if (version == SOCKS5) {
			socks5_sendrsp(ctx, SOCKS5RSP_TTLEXPIRED);
		}
	} break;
	case STATE_ESTABLISHED:
		SOCKS_CTX_LOG(WARNING, ctx, "protocol timeout");
		break;
	case STATE_BIDIRECTIONAL:
	case STATE_UDP_RELAY:
		return;
	default:
		FAILMSGF("unexpected socks_ctx state: %d", ctx->state);
	}
	ctx->s->stats.num_reject_timeout++;
	gc_unref(&ctx->gcbase);
}

static void dialer_cb(struct ev_loop *restrict loop, void *data, const int fd)
{
	struct socks_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		const enum dialer_error err = ctx->dialer.err;
		const int syserr = ctx->dialer.syserr;
		if (syserr != 0) {
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "dialer: %s (%d) %s",
				dialer_strerror(err), syserr, strerror(syserr));
		} else {
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "dialer: %s", dialer_strerror(err));
		}
		ctx->s->stats.num_reject_upstream++;
		socks_senderr(ctx, err, syserr);
		gc_unref(&ctx->gcbase);
		return;
	}
	ctx->dialed_fd = fd;
	if (!socks_sendrsp(ctx, true)) {
		gc_unref(&ctx->gcbase);
		return;
	}

	SOCKS_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_socket);
	dialreq_free(ctx->dialreq);

	socks_start_transfer(loop, ctx);
}

#if WITH_RULESET
static void ruleset_cb(
	struct ev_loop *restrict loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->dialreq = ctx->ruleset_callback.request.req;
	ctx->ruleset_state = NULL;
	if (ctx->dialreq == NULL) {
		ctx->s->stats.num_reject_ruleset++;
	}
	socks_connect(loop, ctx);
}

static void
process_cb(struct ev_loop *restrict loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct socks_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);
	ASSERT(ctx->state == STATE_PROCESS);

	const struct dialaddr *restrict addr = &ctx->addr;
	const size_t cap =
		addr->type == ATYP_DOMAIN ? addr->domain.len + 7 : 64;
	char request[cap];
	const int n = dialaddr_format(request, cap, addr);
	ASSERT(n >= 0 && (size_t)n < cap);
	UNUSED(n);
	const char *username = ctx->auth.username;
	const char *password = ctx->auth.password;
	SOCKS_CTX_LOG_F(
		VERBOSE, ctx, "request: username=%s `%s'", username, request);
	bool ok;
	switch (addr->type) {
	case ATYP_DOMAIN:
		ok = ruleset_resolve(
			ruleset, &ctx->ruleset_state, request, username,
			password, &ctx->ruleset_callback);
		break;
	case ATYP_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, request, username,
			password, &ctx->ruleset_callback);
		break;
	case ATYP_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, request, username,
			password, &ctx->ruleset_callback);
		break;
	default:
		FAILMSGF("unexpected address type: %d", ctx->addr.type);
	}
	if (!ok) {
		(void)socks_sendrsp(ctx, false);
		gc_unref(&ctx->gcbase);
		return;
	}
}
#endif

static void socks_ctx_finalize(struct gcbase *restrict obj)
{
	struct socks_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct socks_ctx, gcbase, obj);
	SOCKS_CTX_LOG_F(VERBOSE, ctx, "closing, state=%d", ctx->state);

	socks_ctx_stop(ctx->s->loop, ctx);
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	if (ctx->state < STATE_ESTABLISHED) {
		dialreq_free(ctx->dialreq);
	}
}

static struct socks_ctx *
socks_ctx_new(struct server *restrict s, const int accepted_fd)
{
	struct socks_ctx *restrict ctx = malloc(sizeof(struct socks_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->accepted_fd = accepted_fd;
	ctx->dialed_fd = -1;

	ev_timer_init(&ctx->w_timeout, timeout_cb, s->conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_socket, recv_cb, accepted_fd, EV_READ);
	ctx->w_socket.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	ev_init(&ctx->ruleset_callback.w_finish, ruleset_cb);
	ctx->ruleset_callback.w_finish.data = ctx;
	ctx->ruleset_state = NULL;
#endif

	ctx->auth.method = SOCKS5AUTH_NOACCEPTABLE;
	ctx->auth.username = NULL;
	ctx->auth.password = NULL;
	BUF_INIT(ctx->rbuf, 0);
	ctx->next = ctx->rbuf.data;
	ctx->dialreq = NULL;
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &cb);
	gc_register(&ctx->gcbase, socks_ctx_finalize);
	return ctx;
}

static void
socks_ctx_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_socket);
	ev_timer_start(loop, &ctx->w_timeout);

	ctx->accepted_ns = clock_monotonic_ns();
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
		CLOSE_FD(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	socks_ctx_start(loop, ctx);
}
