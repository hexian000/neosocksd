/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"

#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "ruleset.h"
#include "ruleset/base.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "transfer.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include <ev.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
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
	STATE_REQUEST,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct socks_ctx {
	struct session ss;
	struct server *s;
	enum socks_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct dialaddr addr;
	struct ev_timer w_timeout;
	union {
		/* during handshake */
		struct {
			struct ev_io w_socket;
			struct {
				uint8_t method;
				const char *username;
				const char *password;
			} auth;
			struct {
				BUFFER_HDR;
				unsigned char data[SOCKS_REQ_MAXLEN];
			} rbuf;
			unsigned char *next;
#if WITH_RULESET
			struct ev_idle w_ruleset;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		/* connected */
		struct {
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct session, struct socks_ctx, ss);

static int format_status(
	char *restrict s, size_t maxlen, const struct socks_ctx *restrict ctx)
{
	char caddr[64];
	format_sa(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if ((ctx)->state != STATE_CONNECT) {
		return snprintf(s, maxlen, "[%d] %s", ctx->accepted_fd, caddr);
	}
	char saddr[64];
	dialaddr_format(saddr, sizeof(saddr), &ctx->addr);
	return snprintf(
		s, maxlen, "[%d] %s -> `%s'", ctx->accepted_fd, caddr, saddr);
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
	case STATE_REQUEST:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_ruleset);
		if (ctx->ruleset_state != NULL) {
			ruleset_cancel(ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
#endif
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
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
	SOCKS_CTX_LOG_F(DEBUG, ctx, "closed, %zu active", stats->num_sessions);
}

static void
socks_ctx_close(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	SOCKS_CTX_LOG_F(VERBOSE, ctx, "close, state=%d", ctx->state);
	socks_ctx_stop(loop, ctx);

	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	session_del(&ctx->ss);
	free(ctx);
}

static void
socks_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct socks_ctx *restrict ctx =
		DOWNCAST(struct session, struct socks_ctx, ss, ss);
	socks_ctx_close(loop, ctx);
}

static void on_established(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	stats->num_success++;
	SOCKS_CTX_LOG_F(
		DEBUG, ctx, "established, %zu active", stats->num_sessions);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct socks_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECTED ||
	       ctx->state == STATE_ESTABLISHED);

	if (ctx->uplink.state == XFER_FINISHED ||
	    ctx->downlink.state == XFER_FINISHED) {
		socks_ctx_close(loop, ctx);
		return;
	}
	if (ctx->state == STATE_CONNECTED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		ctx->state = STATE_ESTABLISHED;
		on_established(loop, ctx);
		return;
	}
}

static bool
send_rsp(struct socks_ctx *restrict ctx, const void *buf, const size_t len)
{
	const int fd = ctx->accepted_fd;
	LOG_BIN_F(VERYVERBOSE, buf, len, "[%d] send_rsp: %zu bytes", fd, len);
	const ssize_t nsend = send(fd, buf, len, 0);
	if (nsend < 0) {
		SOCKS_CTX_LOG_F(WARNING, ctx, "send: %s", strerror(errno));
		return false;
	}
	if ((size_t)nsend != len) {
		SOCKS_CTX_LOG_F(
			WARNING, ctx, "send: %zu < %zu", (size_t)nsend, len);
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

static void socks5_sendrsp(struct socks_ctx *restrict ctx, const uint8_t rsp)
{
	union sockaddr_max addr = {
		.sa.sa_family = AF_INET,
	};
	socklen_t addrlen = sizeof(addr);
	if (ctx->dialed_fd != -1) {
		if (getsockname(ctx->dialed_fd, &addr.sa, &addrlen) != 0) {
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "getsockname: %s", strerror(errno));
		}
	}
	enum {
		SOCKS5_RSPLEN = sizeof(struct socks5_hdr) +
				sizeof(struct in6_addr) + sizeof(in_port_t)
	};
	unsigned char buf[SOCKS5_RSPLEN];

	unsigned char *const hdr = buf;
	write_uint8(hdr + offsetof(struct socks5_hdr, version), SOCKS5);
	write_uint8(hdr + offsetof(struct socks5_hdr, command), rsp);
	write_uint8(hdr + offsetof(struct socks5_hdr, reserved), 0);

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
	CHECK_REVENTS(revents, EV_TIMER);

	struct socks_ctx *restrict ctx = watcher->data;
	switch (ctx->state) {
	case STATE_HANDSHAKE1:
	case STATE_HANDSHAKE2:
	case STATE_HANDSHAKE3:
		SOCKS_CTX_LOG(WARNING, ctx, "handshake timeout");
		break;
	case STATE_REQUEST:
	case STATE_CONNECT: {
		const uint8_t version = read_uint8(ctx->rbuf.data);
		if (version == SOCKS5) {
			socks5_sendrsp(ctx, SOCKS5RSP_TTLEXPIRED);
		}
	} break;
	case STATE_CONNECTED:
		SOCKS_CTX_LOG(WARNING, ctx, "protocol timeout");
		break;
	case STATE_ESTABLISHED:
		return;
	default:
		FAIL();
	}
	socks_ctx_close(loop, ctx);
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
		socks5_sendrsp(ctx, ok ? SOCKS5RSP_SUCCEEDED : SOCKS5RSP_FAIL);
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
	ASSERT(ctx->state == STATE_CONNECT);

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		const int err = ctx->dialer.syserr;
		if (err != 0) {
			SOCKS_CTX_LOG_F(
				DEBUG, ctx,
				"unable to establish client connection: %s",
				strerror(err));
		}
		socks_senderr(ctx, err);
		socks_ctx_close(loop, ctx);
		return;
	}
	ctx->dialed_fd = fd;
	socks_sendrsp(ctx, true);

	SOCKS_CTX_LOG_F(VERBOSE, ctx, "connected, fd=%d", fd);
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_socket);
	dialreq_free(ctx->dialreq);

	if (G.conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ctx->state = STATE_ESTABLISHED;
		on_established(loop, ctx);
	}

	const struct event_cb cb = {
		.func = xfer_state_cb,
		.data = ctx,
	};
	struct server_stats *restrict stats = &ctx->s->stats;
	transfer_init(
		&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static int socks4a_req(struct socks_ctx *restrict ctx)
{
	const char *req = (const char *)ctx->next;
	const size_t maxlen = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	const size_t namelen = strnlen(req, maxlen);
	if (namelen > FQDN_MAX_LENGTH) {
		return -1;
	}
	if (namelen == maxlen) {
		return 1;
	}

	ctx->addr.type = ATYP_DOMAIN;
	struct domain_name *restrict domain = &ctx->addr.domain;
	domain->len = (uint8_t)namelen;
	memcpy(domain->name, ctx->next, namelen);
	ctx->addr.port =
		read_uint16(ctx->rbuf.data + offsetof(struct socks4_hdr, port));

	/* protocol finished */
	return 0;
}

static int socks4_req(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE1);
	ASSERT(ctx->next == ctx->rbuf.data);
	const unsigned char *hdr = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	const size_t want = sizeof(struct socks4_hdr) + 1;
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks4_hdr, command));
	if (command != SOCKS4CMD_CONNECT) {
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "SOCKS4 command not supported: %" PRIu8,
			command);
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return -1;
	}
	char *userid = (char *)hdr + sizeof(struct socks4_hdr);
	const size_t maxlen = ctx->rbuf.len - sizeof(struct socks4_hdr);
	const size_t idlen = strnlen(userid, maxlen);
	if (idlen >= 256) {
		return -1;
	}
	if (idlen == maxlen) {
		return 1;
	}
	ctx->auth.username = userid;
	ctx->auth.password = NULL;

	const uint32_t ip =
		read_uint32(hdr + offsetof(struct socks4_hdr, address));
	const uint32_t mask = UINT32_C(0xFFFFFF00);
	if (!(ip & mask) && (ip & ~mask)) {
		/* SOCKS 4A */
		ctx->next += sizeof(struct socks4_hdr) + idlen + 1;
		return socks4a_req(ctx);
	}

	ctx->addr.type = ATYP_INET;
	memcpy(&ctx->addr.in, hdr + offsetof(struct socks4_hdr, address),
	       sizeof(ctx->addr.in));
	ctx->addr.port = read_uint16(hdr + offsetof(struct socks4_hdr, port));

	/* protocol finished */
	return 0;
}

static int socks5_req(struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_HANDSHAKE3);
	const unsigned char *hdr = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = sizeof(struct socks5_hdr);
	if (len < want) {
		return (int)(want - len);
	}

	const uint8_t version =
		read_uint8(hdr + offsetof(struct socks5_hdr, version));
	if (version != SOCKS5) {
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "SOCKS5: unsupported version %" PRIu8,
			version);
		return -1;
	}
	const uint8_t command =
		read_uint8(hdr + offsetof(struct socks5_hdr, command));
	if (command != SOCKS5CMD_CONNECT) {
		socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "SOCKS5: unsupported command %" PRIu8,
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
	case SOCKS5ADDR_DOMAIN: {
		want += 1;
		if (len < want) {
			return (int)(want - len);
		}
		const uint8_t addrlen =
			read_uint8(hdr + sizeof(struct socks5_hdr));
		want += (size_t)addrlen + sizeof(in_port_t);
	} break;
	default:
		socks5_sendrsp(ctx, SOCKS5RSP_ATYPNOSUPPORT);
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "SOCKS5: unsupported addrtype: %" PRIu8,
			addrtype);
		return -1;
	}
	if (len < want) {
		return (int)(want - len);
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
		FAIL();
	}
	const unsigned char *req = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = 2;
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t ver = read_uint8(req + 0);
	if (ver != 0x01) {
		SOCKS_CTX_LOG(
			ERROR, ctx,
			"SOCKS5: incompatible authentication version");
		return -1;
	}
	const uint8_t ulen = read_uint8(req + 1);
	want += ulen + 1;
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t plen = read_uint8(req + 2 + ulen);
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
	const unsigned char *req = ctx->next;
	const size_t len = ctx->rbuf.len - (ctx->next - ctx->rbuf.data);
	size_t want = sizeof(struct socks5_auth_req);
	if (len < want) {
		return (int)(want - len);
	}
	const uint8_t n =
		read_uint8(req + offsetof(struct socks5_auth_req, nmethods));
	want += n;
	if (len < want) {
		return (int)(want - len);
	}
	const bool auth_required = G.conf->auth_required;
	uint8_t method = SOCKS5AUTH_NOACCEPTABLE;
	const uint8_t *methods = req + sizeof(struct socks5_auth_req);
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
	unsigned char wbuf[sizeof(struct socks5_auth_rsp)];
	write_uint8(wbuf + offsetof(struct socks5_auth_rsp, version), SOCKS5);
	write_uint8(wbuf + offsetof(struct socks5_auth_rsp, method), method);
	if (!send_rsp(ctx, wbuf, sizeof(wbuf))) {
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

static int socks5_dispatch(struct socks_ctx *restrict ctx)
{
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
	FAIL();
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
		return socks5_dispatch(ctx);
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
		SOCKS_CTX_LOG_F(WARNING, ctx, "recv: %s", strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		/* connection is not established yet, we do not expect EOF here */
		SOCKS_CTX_LOG(WARNING, ctx, "recv: early EOF");
		return -1;
	}
	ctx->rbuf.len += (size_t)nrecv;
	LOG_BIN_F(
		VERYVERBOSE, ctx->rbuf.data, ctx->rbuf.len,
		"[%d] recv: %zu bytes", fd, ctx->rbuf.len);
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
		socks_sendrsp(ctx, false);
		socks_ctx_close(loop, ctx);
		return;
	}

	SOCKS_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(&ctx->dialer, loop, ctx->dialreq);
}

#if WITH_RULESET
static void ruleset_cb(struct ev_loop *loop, void *data, struct dialreq *req)
{
	struct socks_ctx *restrict ctx = data;
	ctx->ruleset_state = NULL;
	ctx->dialreq = req;
	socks_connect(loop, ctx);
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct ruleset *restrict ruleset = G.ruleset;
	ASSERT(ruleset != NULL);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_REQUEST);
	const struct dialaddr *restrict addr = &ctx->addr;
	const size_t cap =
		addr->type == ATYP_DOMAIN ? addr->domain.len + 7 : 64;
	char request[cap];
	const int len = dialaddr_format(request, cap, addr);
	CHECK(len >= 0 && (size_t)len < cap);
	const char *username = ctx->auth.username;
	const char *password = ctx->auth.password;
	SOCKS_CTX_LOG_F(
		VERBOSE, ctx, "request: username=%s `%s'", username, request);
	const struct ruleset_request_cb callback = {
		.func = ruleset_cb,
		.loop = loop,
		.data = ctx,
	};
	bool ok;
	switch (addr->type) {
	case ATYP_DOMAIN:
		ok = ruleset_resolve(
			ruleset, &ctx->ruleset_state, request, username,
			password, &callback);
		break;
	case ATYP_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, request, username,
			password, &callback);
		break;
	case ATYP_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, request, username,
			password, &callback);
		break;
	default:
		FAIL();
	}
	if (!ok) {
		socks_sendrsp(ctx, false);
		socks_ctx_close(loop, ctx);
		return;
	}
}
#endif

static struct dialreq *make_dialreq(const struct dialaddr *restrict addr)
{
	struct dialreq *req = dialreq_new(0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	dialaddr_copy(&req->addr, addr);
	return req;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;

	const int ret = socks_recv(ctx, watcher->fd);
	if (ret < 0) {
		/* error */
		socks_ctx_close(loop, ctx);
		return;
	}
	if (ret > 0) {
		/* want more data */
		return;
	}

	/* ignore further io events */
	ev_io_stop(loop, &ctx->w_socket);
	ctx->state = STATE_REQUEST;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;

#if WITH_RULESET
	struct ruleset *restrict ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_ruleset);
		return;
	}
#endif
	ctx->dialreq = make_dialreq(&ctx->addr);
	socks_connect(loop, ctx);
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

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
		w_timeout->data = ctx;
	}
	{
		struct ev_io *restrict w_socket = &ctx->w_socket;
		ev_io_init(w_socket, recv_cb, accepted_fd, EV_READ);
		w_socket->data = ctx;
	}
#if WITH_RULESET
	{
		struct ev_idle *restrict w_ruleset = &ctx->w_ruleset;
		ev_idle_init(w_ruleset, idle_cb);
		w_ruleset->data = ctx;
	}
	ctx->ruleset_state = NULL;
#endif

	ctx->auth.method = SOCKS5AUTH_NOACCEPTABLE;
	ctx->auth.username = NULL;
	ctx->auth.password = NULL;
	BUF_INIT(ctx->rbuf, 0);
	ctx->next = ctx->rbuf.data;
	ctx->dialreq = NULL;
	const struct event_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &cb);
	ctx->ss.close = socks_ss_close;
	session_add(&ctx->ss);
	return ctx;
}

static void
socks_ctx_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_socket);
	ev_timer_start(loop, &ctx->w_timeout);

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
	copy_sa(&ctx->accepted_sa.sa, accepted_sa);
	socks_ctx_start(loop, ctx);
}
