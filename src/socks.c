/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"

#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "binary/serialize.h"
#include "io/io.h"
#include "meta/arraysize.h"
#include "meta/class.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Cap on the distinct target addresses tracked per UDP ASSOCIATE session for
 * the source filter on the target->client direction (see struct socks_ctx). */
#define SOCKS_UDP_TARGETS_MAX 32

/* RFC 1928 section 7: a reassembly queue SHOULD be timed out; the RFC suggests
 * a minimum of 5 seconds. A partial fragment sequence that stops making
 * progress for this long is discarded. */
#define SOCKS_UDP_FRAG_TIMEOUT 5.0

/* never rollback */
enum socks_state {
	STATE_INIT,
	STATE_HANDSHAKE1,
	STATE_HANDSHAKE2,
	STATE_HANDSHAKE3,
	STATE_PROCESS,
	STATE_CONNECT,
	/* waiting for remote to connect to our listen socket */
	STATE_BIND,
	STATE_BIDIRECTIONAL,
	/* relaying UDP datagrams */
	STATE_UDP_RELAY,
};

struct socks_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum socks_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct dialaddr addr;
	ev_timer w_timeout;
	union {
		/* state < STATE_BIDIRECTIONAL */
		struct {
			ev_io w_socket;
			struct {
				uint_least8_t method;
				/* points into rbuf, borrowed until the
				 * request is dispatched */
				struct ruleset_credentials creds;
			} auth;
			struct {
				BUFFER_HDR;
				unsigned char data[SOCKS_REQ_MAXLEN];
			} rbuf;
			unsigned char *next;
			/* total size of the parsed SOCKS request, set once
			 * dispatch finishes; bytes in rbuf beyond this were
			 * pipelined by the client ahead of the reply */
			size_t reqlen;
#if WITH_RULESET
			ev_idle w_process;
			struct ruleset_callback ruleset_callback;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		/* state == STATE_UDP_RELAY */
		struct {
			/* watches dialed_fd, the client-facing UDP socket */
			ev_io w_udp;
			/* watches accepted_fd for TCP close */
			ev_io w_tcp;
			/* per-association reassembly timeout: armed while a
			 * fragment sequence is pending, discards it on expiry */
			ev_timer w_frag;
			/* target-facing UDP sockets, one per address family
			 * (indexed by udp_out_slot), each opened on the first
			 * datagram to a target of that family */
			struct {
				ev_io w_io;
				/* -1 until opened */
				int fd;
				/* opening failed; not retried */
				bool failed;
			} udp_out[2];
			union sockaddr_max udp_peer;
			bool udp_peer_known;
			/* distinct target addresses the client has sent to:
			 * bounded LRU set, most-recent first (index 0 == MRU) */
			union sockaddr_max udp_targets[SOCKS_UDP_TARGETS_MAX];
			uint_least8_t udp_ntargets;
			/* scratch buffer for a single datagram in either
			 * direction; length is tracked per recv, so no BUFFER_HDR
			 * is needed */
			unsigned char ubuf[IO_BUFSIZE];
			/* Fragment reassembly state.
			 * 0 = idle, else the next expected fragment number.
			 */
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

/* Upper bound (excluding NUL) on the prefix format_fd() builds. */
#define FD_PREFIX_STRLEN                                                       \
	(CONSTSTRLEN("[fd:] ") + CONSTSTRLEN("-2147483648") /* max int fd */)

/* The fd-correlation prefix, empty when there is no descriptor left to name:
 * the transfer hand-off moves the accepted fd out of the context, and the
 * number it held may since have been reused by another connection. */
static const char *
format_fd(char *restrict buf, const size_t maxlen, const int fd)
{
	if (fd < 0) {
		return "";
	}
	const int n = snprintf(buf, maxlen, "[fd:%d] ", fd);
	ASSERT(n > 0 && (size_t)n < maxlen);
	(void)n;
	return buf;
}

/* Upper bound (excluding NUL) on a dialaddr rendered by format_addr(). */
#define DIALADDR_LOG_STRLEN LOG_ESCAPE_STRLEN(DIALADDR_STRLEN)

/* Upper bound (excluding NUL) on an escaped user name: SOCKS5 length-prefixes
 * UNAME with one octet (RFC 1929 section 2) and a longer SOCKS4 user ID is
 * refused. */
#define SOCKS_USERNAME_LOG_STRLEN LOG_ESCAPE_STRLEN(UINT8_MAX)

/* The requested destination, escaped for a log line: a SOCKS5 DOMAINNAME is a
 * length-prefixed byte string with no character set of its own (RFC 1928
 * section 5), so the name is whatever the client wrote. Escaping is inline
 * rather than through LOG_TXT_F() because this is a context prefix, which the
 * sinks that render no struct slog_extra must carry too. */
static void format_addr(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	char buf[DIALADDR_STRLEN + 1];
	const int n = dialaddr_format(buf, sizeof(buf), addr);
	if (n < 0 || (size_t)n >= sizeof(buf)) {
		const int ret = snprintf(s, maxlen, "(unavailable)");
		ASSERT(ret > 0);
		(void)ret;
		return;
	}
	(void)log_escape(s, maxlen, buf, (size_t)n);
}

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct socks_ctx *restrict ctx, const int fd)
{
	char fdstr[FD_PREFIX_STRLEN + 1];
	const char *const prefix = format_fd(fdstr, sizeof(fdstr), fd);
	char caddr[64];
	sa_format(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	/* ctx->addr is populated once the request is parsed and stays valid for
	 * the context's lifetime, so include the destination for every state
	 * from STATE_CONNECT onward (transfer-start, UDP-relay-ready, ...). */
	if (ctx->state < STATE_CONNECT) {
		return snprintf(s, maxlen, "%s%s", prefix, caddr);
	}
	char saddr[DIALADDR_LOG_STRLEN + 1];
	format_addr(saddr, sizeof(saddr), &ctx->addr);
	return snprintf(s, maxlen, "%s%s -> `%s'", prefix, caddr, saddr);
}

/* Upper bound (excluding NUL) on the line format_status() builds:
 * "[fd:N] caddr -> `saddr'", where caddr is a sa_format() sockaddr (<= 63) and
 * saddr an escaped dialaddr. */
#define SOCKS_STATUS_STRLEN                                                    \
	(FD_PREFIX_STRLEN + 64 /* caddr sa_format buffer */ +                  \
	 CONSTSTRLEN(" -> `'") + DIALADDR_LOG_STRLEN)

/* Log with an explicit fd for the correlation prefix, for the hand-off path
 * that has already moved the accepted fd out of the context. */
#define SOCKS_FD_LOG_F(level, ctx, fd, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char status_str[SOCKS_STATUS_STRLEN + 1];                      \
		const int nstatus = format_status(                             \
			status_str, sizeof(status_str), (ctx), (fd));          \
		ASSERT(nstatus > 0);                                           \
		LOG_F(level, "%.*s: " format, nstatus, status_str,             \
		      __VA_ARGS__);                                            \
	} while (0)
#define SOCKS_CTX_LOG_F(level, ctx, format, ...)                               \
	SOCKS_FD_LOG_F(level, ctx, (ctx)->accepted_fd, format, __VA_ARGS__)
#define SOCKS_CTX_LOG(level, ctx, message)                                     \
	SOCKS_CTX_LOG_F(level, ctx, "%s", message)

static bool
send_rsp(struct socks_ctx *restrict ctx, const void *buf, const size_t len)
{
	const int fd = ctx->accepted_fd;
	LOG_BIN_F(
		VERYVERBOSE, buf, len, 0, "[fd:%d] send_rsp: %zu bytes", fd,
		len);
	ssize_t nsend;
	do {
		nsend = send(fd, buf, len, 0);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			DEBUG, ctx, "send: (%d) %s", err, strerror(err));
		return false;
	}
	if ((size_t)nsend != len) {
		SOCKS_CTX_LOG_F(DEBUG, ctx, "send: %zd < %zu", nsend, len);
		return false;
	}
	ctx->s->stats.byt_client_send += (uint_least64_t)len;
	return true;
}

static bool
socks4_sendrsp(struct socks_ctx *restrict ctx, const uint_fast8_t rsp)
{
	unsigned char buf[SOCKS4_HDR_LEN];
	const struct socks4_hdr h = {
		.version = 0,
		.command = rsp,
	};
	socks4hdr_write(buf, &h);
	return send_rsp(ctx, buf, SOCKS4_HDR_LEN);
}

static bool socks5_sendrsp_addr(
	struct socks_ctx *restrict ctx, const uint_fast8_t rsp,
	const union sockaddr_max *restrict addr)
{
	unsigned char buf[SOCKS5_RSP_MAXLEN];
	struct socks5_hdr h = {
		.version = SOCKS5,
		.command = rsp,
		.reserved = 0,
	};
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

/* Reduce an IPv4-mapped IPv6 address (::ffff:a.b.c.d), the form a dual-stack
 * socket reports an IPv4 endpoint in, to its plain IPv4 form. Any other address
 * is left unchanged. */
static void unmap_v4mapped(union sockaddr_max *restrict sa)
{
	if (sa->sa.sa_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&sa->in6.sin6_addr)) {
		return;
	}
	const in_port_t port = sa->in6.sin6_port;
	struct in_addr addr;
	memcpy(&addr, &sa->in6.sin6_addr.s6_addr[12], sizeof(addr));
	*sa = (union sockaddr_max){
		.in = {
			.sin_family = AF_INET,
			.sin_port = port,
			.sin_addr = addr,
		},
	};
}

/* Local endpoint of the dialed socket, unmapped. On failure *out is left as the
 * unspecified IPv4 address and false is returned. */
static bool dialed_sockname(
	const struct socks_ctx *restrict ctx, union sockaddr_max *restrict out)
{
	*out = (union sockaddr_max){ 0 };
	socklen_t len = sizeof(*out);
	if (getsockname(ctx->dialed_fd, &out->sa, &len) != 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "getsockname: (%d) %s", err, strerror(err));
		out->sa.sa_family = AF_INET;
		return false;
	}
	unmap_v4mapped(out);
	return true;
}

/* RFC 1928 BND.ADDR for a wildcard-bound BIND/UDP socket: the host the client
 * reached us on (local end of the TCP control connection) with the ephemeral
 * port of the bound socket, whose own name is the fallback. */
static void socks_bound_addr(
	const struct socks_ctx *restrict ctx, union sockaddr_max *restrict out)
{
	union sockaddr_max bound;
	if (!dialed_sockname(ctx, &bound)) {
		*out = bound;
		return;
	}
	union sockaddr_max local = { 0 };
	socklen_t locallen = sizeof(local);
	if (getsockname(ctx->accepted_fd, &local.sa, &locallen) != 0 ||
	    local.sa.sa_family != bound.sa.sa_family) {
		*out = bound;
		return;
	}
	*out = local;
	switch (out->sa.sa_family) {
	case AF_INET:
		out->in.sin_port = bound.in.sin_port;
		break;
	case AF_INET6:
		out->in6.sin6_port = bound.in6.sin6_port;
		break;
	default:
		break;
	}
	unmap_v4mapped(out);
}

/* Every call site reaching here with a live dialed_fd holds a wildcard-bound
 * BIND/UDP socket; the connected-socket reply is built in socks_sendrsp. */
static bool
socks5_sendrsp(struct socks_ctx *restrict ctx, const uint_fast8_t rsp)
{
	union sockaddr_max addr = {
		.sa.sa_family = AF_INET,
	};
	if (ctx->dialed_fd != -1) {
		socks_bound_addr(ctx, &addr);
	}
	return socks5_sendrsp_addr(ctx, rsp, &addr);
}

static bool socks_sendrsp(struct socks_ctx *restrict ctx, const bool ok)
{
	const uint_fast8_t version = read_uint8(ctx->rbuf.data);
	switch (version) {
	case SOCKS4:
		return socks4_sendrsp(
			ctx, ok ? SOCKS4RSP_GRANTED : SOCKS4RSP_REJECTED);
	case SOCKS5:
		if (!ok) {
			return socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		}
		/* RFC 1928 section 6: on CONNECT, BND is the endpoint the server
		 * connected from, which the outbound socket reports directly. */
		ASSERT(ctx->dialed_fd != -1);
		{
			union sockaddr_max addr;
			(void)dialed_sockname(ctx, &addr);
			return socks5_sendrsp_addr(
				ctx, SOCKS5RSP_SUCCEEDED, &addr);
		}
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

/* `off` is the offset of the domain name from rbuf.data, computed fresh by
 * the caller on every invocation -- see the re-entrancy note in socks4_req(). */
static int socks4a_req(struct socks_ctx *restrict ctx, const size_t off)
{
	const char *const restrict name = (const char *)ctx->rbuf.data + off;
	const size_t maxlen = ctx->rbuf.len - off;
	const size_t namelen = strnlen(name, maxlen);
	if (namelen > FQDN_MAX_LENGTH) {
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
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
	ctx->reqlen = off + namelen + 1;
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
	const char *const userid = (const char *)hdr + SOCKS4_HDR_LEN;
	const size_t maxlen = ctx->rbuf.len - SOCKS4_HDR_LEN;
	const size_t idlen = strnlen(userid, maxlen);
	if (idlen >= 256) {
		socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		return -1;
	}
	if (idlen == maxlen) {
		return 1;
	}
	/* SOCKS4 carries a user ID and no password */
	ctx->auth.creds = (struct ruleset_credentials){
		.username = userid,
		.username_len = idlen,
	};
	ctx->addr.port = h.port;

	const uint_fast32_t ip = h.address;
	const uint_fast32_t mask = UINT32_C(0xFFFFFF00);
	if (!(ip & mask) && (ip & ~mask)) {
		/* SOCKS 4A: with no sub-state for SOCKS4/4A this function is
		 * re-entered from scratch on every recv() event, so the domain
		 * offset is recomputed here rather than cached in ctx->next. */
		return socks4a_req(ctx, SOCKS4_HDR_LEN + idlen + 1);
	}

	ctx->addr.type = ATYP_INET;
	write_uint32(&ctx->addr.in, h.address);

	/* protocol finished */
	ctx->reqlen = SOCKS4_HDR_LEN + idlen + 1;
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
		/* RFC 1928 section 5 length-prefixes DST.ADDR and names it a
		 * fully qualified domain name, which admits no null byte (RFC
		 * 1035 section 2.3.1, RFC 1123 section 2.1). Nothing downstream
		 * can carry one either: the resolver and the ruleset binding
		 * both take a null-terminated name. Accepting it would rename
		 * the request to the bytes before the null and then decide,
		 * log and dial that instead, so refuse it here. */
		if (memchr(rawaddr, '\0', addrlen) != NULL) {
			socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
			SOCKS_CTX_LOG(
				ERROR, ctx,
				"SOCKS5: null byte in the requested domain name");
			return -1;
		}
		ctx->addr.type = ATYP_DOMAIN;
		struct domain_name *restrict domain = &ctx->addr.domain;
		domain->len = addrlen;
		memcpy(domain->name, rawaddr, addrlen);
		ctx->addr.port = read_uint16(rawaddr + addrlen);
	} break;
	default:
		FAILMSGF("unexpected socks5 address type: %d", addrtype);
	}

	/* protocol finished; unlike SOCKS4, ctx->next has already advanced
	 * past the auth negotiation (and auth) stage(s), so the total size
	 * from rbuf.data must include that offset */
	ctx->reqlen = (size_t)(ctx->next - ctx->rbuf.data) + want;
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
		SOCKS_CTX_LOG(
			ERROR, ctx, "SOCKS5: empty authentication credentials");
		(void)send_rsp(ctx, wbuf, sizeof(wbuf));
		return -1;
	}
	/* RFC 1929 length-prefixes both fields, so any octet is legal wire data;
	 * carry the lengths instead of null-terminating the fields */
	ctx->auth.creds = (struct ruleset_credentials){
		.username = (const char *)req + 2,
		.username_len = ulen,
		.password = (const char *)req + 2 + ulen + 1,
		.password_len = plen,
	};

	/* authentication is always successful because the request is unknown yet */
	/* STATUS = SUCCESS */
	wbuf[1] = 0x00;
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
	const struct socks5_auth_rsp ar = {
		.version = SOCKS5,
		.method = method,
	};
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
	ctx->auth.method = (uint_least8_t)method;

	ctx->next += want;
	ctx->state = STATE_HANDSHAKE2;
	return socks5_auth(ctx);
}

static int socks_dispatch(struct socks_ctx *restrict ctx)
{
	if (ctx->rbuf.len < 1) {
		return 1;
	}
	const uint_fast8_t version = read_uint8(ctx->rbuf.data);
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
	ssize_t nrecv;
	do {
		nrecv = recv(fd, buf, n, 0);
	} while (nrecv < 0 && errno == EINTR);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
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
	ctx->s->stats.byt_client_recv += (uint_least64_t)nrecv;
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
		ctx->s->resolver, ctx->s);
}

/* A zero port constrains nothing; otherwise the peer's port must equal it. */
static bool peer_port_matches(
	const union sockaddr_max *restrict peer_sa,
	const uint_least16_t req_port)
{
	if (req_port == 0) {
		return true;
	}
	switch (peer_sa->sa.sa_family) {
	case AF_INET:
		return peer_sa->in.sin_port == htons(req_port);
	case AF_INET6:
		return peer_sa->in6.sin6_port == htons(req_port);
	default:
		break;
	}
	return false;
}

static bool addr_unspecified(const union sockaddr_max *restrict sa)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		return sa->in.sin_addr.s_addr == htonl(INADDR_ANY);
	case AF_INET6:
		return IN6_IS_ADDR_UNSPECIFIED(&sa->in6.sin6_addr);
	default:
		break;
	}
	return false;
}

/* A BIND request's DST.ADDR and DST.PORT constrain the expected peer
 * independently, and a wildcard address does not constrain the address family
 * either: a dual-stack listener may accept a peer of either family. */
static bool bind_peer_matches_request(
	const struct socks_ctx *restrict ctx,
	const union sockaddr_max *restrict peer_sa)
{
	const uint_least16_t req_port = ctx->addr.port;
	union sockaddr_max req;
	switch (ctx->addr.type) {
	case ATYP_INET:
		req = (union sockaddr_max){
			.in = {
				.sin_family = AF_INET,
				.sin_port = htons(req_port),
				.sin_addr = ctx->addr.in,
			},
		};
		break;
	case ATYP_INET6:
		req = (union sockaddr_max){
			.in6 = {
				.sin6_family = AF_INET6,
				.sin6_port = htons(req_port),
				.sin6_addr = ctx->addr.in6,
			},
		};
		break;
	case ATYP_DOMAIN:
		/* a name is not resolved here, so only its port constrains */
		return peer_port_matches(peer_sa, req_port);
	default:
		FAILMSGF("unexpected address type: %d", ctx->addr.type);
	}
	/* the peer arrives unmapped, so reduce a mapped request literal too */
	unmap_v4mapped(&req);
	if (addr_unspecified(&req)) {
		return peer_port_matches(peer_sa, req_port);
	}
	return sa_matches(&req.sa, &peer_sa->sa);
}

static void
socks_start_transfer(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/* Enter STATE_BIDIRECTIONAL before server_commit_session(): on failure
	 * it gc_unref()s the context, and the finalizer must then treat it as
	 * handed off rather than decrement num_halfopen a second time or free
	 * the released dialreq again. */
	struct server_stats *restrict stats = &ctx->s->stats;
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	stats->num_halfopen--;
	SOCKS_FD_LOG_F(
		DEBUG, ctx, acc_fd, "transfer start: [%d<->%d]", acc_fd,
		dial_fd);
	const size_t cur =
		server_commit_session(ctx->s, &ctx->gcbase, acc_fd, dial_fd);
	if (cur == 0) {
		return;
	}
	SOCKS_FD_LOG_F(DEBUG, ctx, acc_fd, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

static void
bind_accept_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_BIND);

	union sockaddr_max peer_sa = { 0 };
	socklen_t peer_len = sizeof(peer_sa);
	const int conn_fd = accept(ctx->dialed_fd, &peer_sa.sa, &peer_len);
	if (conn_fd < 0) {
		const int err = errno;
		if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK ||
		    err == ECONNABORTED) {
			return;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "accept: (%d) %s", err, strerror(err));
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	SOCKS_CTX_LOG_F(VERBOSE, ctx, "BIND: accepted [fd:%d]", conn_fd);
	unmap_v4mapped(&peer_sa);
	if (!bind_peer_matches_request(ctx, &peer_sa)) {
		char peer_str[64];
		sa_format(peer_str, sizeof(peer_str), &peer_sa.sa);
		char expect_str[DIALADDR_LOG_STRLEN + 1];
		format_addr(expect_str, sizeof(expect_str), &ctx->addr);
		SOCKS_CTX_LOG_F(
			WARNING, ctx,
			"BIND peer mismatch (expected `%s', got `%s'), allowing",
			expect_str, peer_str);
	}
	/* both setters return the errno; they never set the global one */
	int setup_err = socket_set_cloexec(conn_fd);
	if (setup_err == 0) {
		setup_err = socket_set_nonblock(conn_fd);
	}
	if (setup_err != 0) {
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "socket setup: (%d) %s", setup_err,
			strerror(setup_err));
		socket_close(conn_fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return;
	}
	/* best-effort tuning; failure does not affect correctness */
	const struct config *restrict conf = ctx->s->conf;
	LOG_SOCKOPT(
		"socket_set_tcp",
		socket_set_tcp(conn_fd, conf->tcp_nodelay, conf->tcp_keepalive));
#if WITH_TCP_KEEPALIVE_PARAMS
	if (conf->tcp_keepalive) {
		socket_set_keepalive(
			conn_fd, conf->tcp_keepidle, conf->tcp_keepintvl,
			conf->tcp_keepcnt);
	}
#endif
	LOG_SOCKOPT(
		"socket_set_buffer",
		socket_set_buffer(conn_fd, conf->tcp_sndbuf, conf->tcp_rcvbuf));
	ev_io_stop(loop, &ctx->w_socket);
	socket_close(ctx->dialed_fd);
	ctx->dialed_fd = conn_fd;
	if (!socks5_sendrsp_addr(ctx, SOCKS5RSP_SUCCEEDED, &peer_sa)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	/* Any client bytes pipelined after the BIND request were never
	 * forwarded to the peer; replay them now, mirroring socks_commit's
	 * readahead handling on the CONNECT path. */
	const size_t readahead = ctx->rbuf.len - ctx->reqlen;
	if (readahead > 0 && !forward_readahead(
				     conn_fd, ctx->rbuf.data + ctx->reqlen,
				     readahead, &ctx->s->byt_up)) {
		SOCKS_CTX_LOG(
			WARNING, ctx,
			"failed to forward pipelined bytes to peer");
		gc_unref(&ctx->gcbase);
		return;
	}
	dialreq_free(ctx->dialreq);
	socks_start_transfer(loop, ctx);
}

/* Creates a non-blocking socket of the given type, bound to INADDR_ANY:0 on
 * the specified address family. On any error, sends a SOCKS5 failure response,
 * releases the context via gc_unref, and returns -1. */
static int socks_open_bound_fd(
	struct socks_ctx *restrict ctx, const int family, const int type)
{
	const int fd = socket(family, type, 0);
	if (fd < 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "socket: (%d) %s", err, strerror(err));
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return -1;
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
		if (bind(fd, &bindsa.sa, bindlen) != 0) {
			const int err = errno;
			SOCKS_CTX_LOG_F(
				ERROR, ctx, "bind: (%d) %s", err,
				strerror(err));
			socket_close(fd);
			socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
			gc_unref(&ctx->gcbase);
			return -1;
		}
	}
	/* both setters return the errno; they never set the global one */
	int setup_err = socket_set_cloexec(fd);
	if (setup_err == 0) {
		setup_err = socket_set_nonblock(fd);
	}
	if (setup_err != 0) {
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "socket setup: (%d) %s", setup_err,
			strerror(setup_err));
		socket_close(fd);
		socks5_sendrsp(ctx, SOCKS5RSP_FAIL);
		gc_unref(&ctx->gcbase);
		return -1;
	}
	return fd;
}

static void
socks_bind_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_PROCESS);
	const int family = ctx->accepted_sa.sa.sa_family;
	/* Not bound to --netdev, which binds outgoing connections: the peer
	 * connects in to the advertised BND.ADDR, the address the client reached
	 * us on, and a device-bound listener would refuse it arriving over any
	 * other interface. */
	const int listen_fd = socks_open_bound_fd(ctx, family, SOCK_STREAM);
	if (listen_fd < 0) {
		return;
	}
	if (listen(listen_fd, 1) != 0) {
		const int err = errno;
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "listen: (%d) %s", err, strerror(err));
		socket_close(listen_fd);
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

/* Parse SOCKS5 UDP header into *sa, *salen, and *hdr_len_out. */
static bool udp_parse_addr(
	union sockaddr_max *restrict sa, socklen_t *restrict salen,
	size_t *restrict hdr_len_out, const unsigned char *restrict buf,
	const size_t buflen)
{
	if (buflen < SOCKS5_UDP_HDR_LEN) {
		return false;
	}
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
		*hdr_len_out = SOCKS5_UDP_HDR_IPV4LEN;
		break;
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
		*hdr_len_out = SOCKS5_UDP_HDR_IPV6LEN;
		break;
	default:
		return false;
	}
	/* a target the client wrote as ::ffff:a.b.c.d is the same target it
	 * would have written as a.b.c.d, and replies arrive in this form */
	unmap_v4mapped(sa);
	*salen = sa_len(&sa->sa);
	return true;
}

/* Record a target the client sent a datagram to as the most-recently-used entry
 * of the bounded set, so a later reply from it passes the source filter. When
 * the set is full the least-recently-used entry is evicted. */
static void udp_target_remember(
	struct socks_ctx *restrict ctx, const struct sockaddr *restrict sa)
{
	size_t i;
	for (i = 0; i < ctx->udp_ntargets; i++) {
		if (sa_equals(&ctx->udp_targets[i].sa, sa)) {
			break;
		}
	}
	if (i == ctx->udp_ntargets) {
		/* not present: grow, or reuse the least-recent (last) slot */
		if (ctx->udp_ntargets < SOCKS_UDP_TARGETS_MAX) {
			ctx->udp_ntargets++;
		}
		i = (size_t)ctx->udp_ntargets - 1;
	}
	/* move slot i to the front (index 0 == most recent) */
	memmove(&ctx->udp_targets[1], &ctx->udp_targets[0],
		i * sizeof(ctx->udp_targets[0]));
	sa_copy(&ctx->udp_targets[0].sa, sa);
}

/* True if a datagram source matches a target the client has sent to. */
static bool udp_target_known(
	const struct socks_ctx *restrict ctx,
	const struct sockaddr *restrict sa)
{
	for (size_t i = 0; i < ctx->udp_ntargets; i++) {
		if (sa_equals(&ctx->udp_targets[i].sa, sa)) {
			return true;
		}
	}
	return false;
}

/* Receive one datagram on @p fd into ubuf, with its source in *from_sa as the
 * socket reports it. Returns false when there is nothing to relay; on a fatal
 * error it has also released the context. */
static bool udp_recv(
	struct socks_ctx *restrict ctx, const int fd,
	union sockaddr_max *restrict from_sa, size_t *restrict len)
{
	struct iovec riov = {
		.iov_base = ctx->ubuf,
		.iov_len = IO_BUFSIZE,
	};
	struct msghdr rmsg = {
		.msg_name = from_sa,
		.msg_namelen = sizeof(*from_sa),
		.msg_iov = &riov,
		.msg_iovlen = 1,
	};
	const ssize_t nrecv = recvmsg(fd, &rmsg, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
			return false;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "recvmsg: (%d) %s", err, strerror(err));
		gc_unref(&ctx->gcbase);
		return false;
	}
	if (rmsg.msg_flags & MSG_TRUNC) {
		/* A datagram larger than ubuf was truncated by the kernel;
		 * forwarding the partial payload would silently corrupt it. */
		SOCKS_CTX_LOG_F(
			DEBUG, ctx,
			"UDP: dropping datagram larger than the %d-byte buffer",
			(int)IO_BUFSIZE);
		return false;
	}
	*len = (size_t)nrecv;
	return true;
}

/* Target -> client: prepend the SOCKS5 UDP header naming the target and send
 * the datagram to the client through the client-facing socket. */
static void
udp_target_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);
	/* a target socket is opened only to forward a client datagram */
	ASSERT(ctx->udp_peer_known);

	union sockaddr_max from_sa;
	size_t nrecv;
	if (!udp_recv(ctx, watcher->fd, &from_sa, &nrecv)) {
		return;
	}
	/* a dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d, which
	 * matches neither a remembered target nor SOCKS5 ATYP = IPv4 */
	unmap_v4mapped(&from_sa);
	if (!udp_target_known(ctx, &from_sa.sa)) {
		/* Source filter: drop a datagram from a host the client has not
		 * sent to, so an off-path host cannot inject unsolicited UDP
		 * into the client session. Remote-triggerable, so log at DEBUG. */
		char src_str[64];
		sa_format(src_str, sizeof(src_str), &from_sa.sa);
		SOCKS_CTX_LOG_F(
			DEBUG, ctx,
			"UDP: dropping datagram from unsolicited source %s",
			src_str);
		return;
	}
	unsigned char hdr_buf[SOCKS5_UDP_HDR_MAXLEN];
	size_t hdr_len;
	struct socks5_udp_hdr udph = {
		.reserved = { 0, 0 },
		.frag = 0,
	};
	switch (from_sa.sa.sa_family) {
	case AF_INET:
		udph.addrtype = SOCKS5ADDR_IPV4;
		memcpy(hdr_buf + SOCKS5_UDP_HDR_LEN, &from_sa.in.sin_addr,
		       sizeof(from_sa.in.sin_addr));
		hdr_len = SOCKS5_UDP_HDR_LEN + sizeof(from_sa.in.sin_addr);
		memcpy(hdr_buf + hdr_len, &from_sa.in.sin_port,
		       sizeof(from_sa.in.sin_port));
		hdr_len += sizeof(from_sa.in.sin_port);
		break;
	case AF_INET6:
		udph.addrtype = SOCKS5ADDR_IPV6;
		memcpy(hdr_buf + SOCKS5_UDP_HDR_LEN, &from_sa.in6.sin6_addr,
		       sizeof(from_sa.in6.sin6_addr));
		hdr_len = SOCKS5_UDP_HDR_LEN + sizeof(from_sa.in6.sin6_addr);
		memcpy(hdr_buf + hdr_len, &from_sa.in6.sin6_port,
		       sizeof(from_sa.in6.sin6_port));
		hdr_len += sizeof(from_sa.in6.sin6_port);
		break;
	default:
		/* Unexpected address family, discard. */
		return;
	}
	socks5udphdr_write(hdr_buf, &udph);
	struct iovec iov[2] = {
		{ .iov_base = hdr_buf, .iov_len = hdr_len },
		{ .iov_base = ctx->ubuf, .iov_len = nrecv },
	};
	const struct msghdr msg = {
		.msg_name = &ctx->udp_peer.sa,
		.msg_namelen = sa_len(&ctx->udp_peer.sa),
		.msg_iov = iov,
		.msg_iovlen = 2,
	};
	ssize_t nsend;
	do {
		nsend = sendmsg(ctx->dialed_fd, &msg, 0);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		if (err != EAGAIN && err != EWOULDBLOCK && err != ENOBUFS) {
			SOCKS_CTX_LOG_F(
				DEBUG, ctx, "sendmsg to client: (%d) %s", err,
				strerror(err));
		}
	} else {
		xfer_count(&ctx->s->byt_down, (size_t)nsend);
	}
	(void)loop;
}

static size_t udp_out_slot(const int family)
{
	return family == AF_INET6 ? 1 : 0;
}

/* The target-facing socket for @p family, opened on first use. It is separate
 * from the client-facing socket so that it can reach a target of either family
 * whatever the client's, and be bound to --netdev without also binding the
 * client leg. Returns -1 when the socket cannot be opened, which is reported
 * once per association. */
static int udp_out_fd(
	struct ev_loop *restrict loop, struct socks_ctx *restrict ctx,
	const int family)
{
	const size_t i = udp_out_slot(family);
	if (ctx->udp_out[i].fd != -1) {
		return ctx->udp_out[i].fd;
	}
	if (ctx->udp_out[i].failed) {
		return -1;
	}
	int err = 0;
	const int fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0) {
		err = errno;
	} else {
		/* both setters return the errno; they never set the global
		 * one */
		err = socket_set_cloexec(fd);
		if (err == 0) {
			err = socket_set_nonblock(fd);
		}
		if (err != 0) {
			socket_close(fd);
		}
	}
	if (err != 0) {
		SOCKS_CTX_LOG_F(
			WARNING, ctx,
			"UDP: dropping datagrams to %s targets, no socket: (%d) %s",
			family == AF_INET6 ? "IPv6" : "IPv4", err,
			strerror(err));
		ctx->udp_out[i].failed = true;
		return -1;
	}
#if WITH_NETDEVICE
	const struct config *restrict conf = ctx->s->conf;
	if (conf->netdev != NULL) {
		socket_bind_netdev(fd, conf->netdev);
	}
#endif
	ev_io_init(&ctx->udp_out[i].w_io, udp_target_cb, fd, EV_READ);
	ctx->udp_out[i].w_io.data = ctx;
	ev_io_start(loop, &ctx->udp_out[i].w_io);
	ctx->udp_out[i].fd = fd;
	return fd;
}

/* Client -> target: send a payload to a target through the target-facing
 * socket of its family, authorizing replies from it for the source filter. */
static void udp_send_target(
	struct ev_loop *restrict loop, struct socks_ctx *restrict ctx,
	const void *restrict buf, const size_t len,
	const union sockaddr_max *restrict target, const socklen_t target_len)
{
	if (!check_outbound_sa(ctx->s->conf, &target->sa)) {
		return;
	}
	const int fd = udp_out_fd(loop, ctx, target->sa.sa_family);
	if (fd < 0) {
		return;
	}
	udp_target_remember(ctx, &target->sa);
	ssize_t nsend;
	do {
		nsend = sendto(fd, buf, len, 0, &target->sa, target_len);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		const int err = errno;
		if (err != EAGAIN && err != EWOULDBLOCK && err != ENOBUFS) {
			/* client-controlled target, so a per-datagram send
			 * failure is remote-triggerable: log at DEBUG to avoid a
			 * flood, matching the sibling discard paths */
			SOCKS_CTX_LOG_F(
				DEBUG, ctx, "sendto target: (%d) %s", err,
				strerror(err));
		}
		return;
	}
	xfer_count(&ctx->s->byt_up, (size_t)nsend);
}

static void udp_frag_reset(struct socks_ctx *restrict ctx)
{
	ctx->frag_next = 0;
	BUF_INIT(ctx->frag_buf, 0);
}

/* Keep the reassembly timer armed exactly while a fragment sequence is pending:
 * each in-order fragment re-arms it (resetting the countdown), and completion
 * or reset stops it. Called from the relay callback, which owns the loop. */
static void udp_frag_timer_sync(
	struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	if (ctx->frag_next != 0) {
		ev_timer_again(loop, &ctx->w_frag);
	} else {
		ev_timer_stop(loop, &ctx->w_frag);
	}
}

static void udp_frag_timeout_cb(
	struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);
	/* Remote-triggerable (a client that stalls mid-sequence), so log at
	 * DEBUG like the sibling UDP discard paths. */
	SOCKS_CTX_LOG(
		DEBUG, ctx,
		"UDP frag: reassembly timed out, discarding partial sequence");
	udp_frag_reset(ctx);
	ev_timer_stop(loop, watcher);
}

static void
udp_frag_flush(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	udp_send_target(
		loop, ctx, ctx->frag_buf.data, ctx->frag_buf.len,
		&ctx->frag_target, ctx->frag_target_len);
	udp_frag_reset(ctx);
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

/* Fragment assembly: reassemble into frag_buf, forward on last fragment;
 * discard out-of-order/overflow. Discards are remote-driven and per-datagram,
 * so they log at DEBUG. */
static void udp_frag_client_recv(
	struct ev_loop *restrict loop, struct socks_ctx *restrict ctx,
	const size_t nrecv, const uint_fast8_t frag)
{
	const uint_fast8_t pos = frag & UINT8_C(0x7F);
	const bool is_last = (frag & SOCKS5_UDP_FRAG_LAST) != 0;
	const unsigned char *const buf = ctx->ubuf;

	if (pos == 1) {
		/* First fragment: save target address and start accumulation */
		if (ctx->frag_next != 0) {
			SOCKS_CTX_LOG(
				DEBUG, ctx,
				"UDP frag: new sequence discards in-progress one");
			/* drop it before parsing: udp_parse_addr clears
			 * frag_target and can then fail */
			udp_frag_reset(ctx);
		}
		size_t hdr_len;
		if (!udp_parse_addr(
			    &ctx->frag_target, &ctx->frag_target_len, &hdr_len,
			    buf, nrecv)) {
			return;
		}
		/* nrecv <= IO_BUFSIZE (the recvfrom bound) and hdr_len >=
		 * SOCKS5_UDP_HDR_IPV4LEN, so payload_len always fits frag_buf */
		const size_t payload_len = nrecv - hdr_len;
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
				DEBUG, ctx,
				"UDP frag: out-of-order, discarding sequence");
			udp_frag_reset(ctx);
		} else {
			SOCKS_CTX_LOG(
				DEBUG, ctx,
				"UDP frag: unexpected fragment, discarding");
		}
		return;
	}

	/* Subsequent in-order fragment: target address repeats but we use the
	 * one saved from fragment 1 */
	const int hl = udp_hdr_len(buf, nrecv);
	if (hl < 0) {
		SOCKS_CTX_LOG(
			DEBUG, ctx,
			"UDP frag: malformed fragment, discarding sequence");
		udp_frag_reset(ctx);
		return;
	}
	const size_t hdr_len = (size_t)hl;
	const size_t payload_len = nrecv - hdr_len;
	if (payload_len > IO_BUFSIZE - ctx->frag_buf.len) {
		SOCKS_CTX_LOG(
			DEBUG, ctx,
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

/* True if a datagram from @p from_sa is the client's. The first one binds the
 * client identity, and must come from the host of the authenticated TCP client;
 * the UDP source port legitimately differs. Later ones must come from exactly
 * that address. The client is remembered, and replied to, in the form this
 * socket reports it in: an AF_INET6 socket on a dual-stack listener reports an
 * IPv4 client as ::ffff:a.b.c.d, and not every platform accepts a plain IPv4
 * destination on it. A mismatch is remote-triggerable, so it logs at DEBUG. */
static bool udp_from_client(
	struct socks_ctx *restrict ctx,
	const union sockaddr_max *restrict from_sa)
{
	if (ctx->udp_peer_known) {
		if (sa_equals(&from_sa->sa, &ctx->udp_peer.sa)) {
			return true;
		}
		char src_str[64];
		sa_format(src_str, sizeof(src_str), &from_sa->sa);
		SOCKS_CTX_LOG_F(
			DEBUG, ctx,
			"UDP: dropping datagram from %s: not the client",
			src_str);
		return false;
	}
	union sockaddr_max client = ctx->accepted_sa;
	unmap_v4mapped(&client);
	switch (client.sa.sa_family) {
	case AF_INET:
		client.in.sin_port = 0;
		break;
	case AF_INET6:
		client.in6.sin6_port = 0;
		break;
	default:
		break;
	}
	union sockaddr_max src = *from_sa;
	unmap_v4mapped(&src);
	if (!sa_matches(&client.sa, &src.sa)) {
		char src_str[64];
		sa_format(src_str, sizeof(src_str), &from_sa->sa);
		SOCKS_CTX_LOG_F(
			DEBUG, ctx,
			"UDP: dropping first datagram from %s: source does not match the client",
			src_str);
		return false;
	}
	sa_copy(&ctx->udp_peer.sa, &from_sa->sa);
	ctx->udp_peer_known = true;
	return true;
}

/* Client -> target: strip the SOCKS5 UDP header and forward the payload. Only
 * the client sends to the client-facing socket; target replies arrive on the
 * target-facing sockets instead (udp_target_cb). */
static void
udp_client_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);

	union sockaddr_max from_sa;
	size_t nrecv;
	if (!udp_recv(ctx, ctx->dialed_fd, &from_sa, &nrecv)) {
		return;
	}
	if (!udp_from_client(ctx, &from_sa)) {
		return;
	}
	if (nrecv < SOCKS5_UDP_HDR_LEN) {
		/* Too short, discard. */
		return;
	}
	struct socks5_udp_hdr udph;
	socks5udphdr_read(&udph, ctx->ubuf);
	const uint_fast8_t frag = udph.frag;
	if (frag != 0) {
		udp_frag_client_recv(loop, ctx, nrecv, frag);
		udp_frag_timer_sync(loop, ctx);
		return;
	}
	/* RFC 1928 section 7 reinitializes the reassembly queue upon a datagram
	 * whose FRAG is below the highest one seen; FRAG 0 is below any
	 * in-progress fragment. */
	if (ctx->frag_next != 0) {
		SOCKS_CTX_LOG(
			DEBUG, ctx,
			"UDP frag: standalone datagram discards in-progress sequence");
		udp_frag_reset(ctx);
	}
	udp_frag_timer_sync(loop, ctx);
	/* Non-fragmented datagram: parse target and forward payload */
	union sockaddr_max target_sa;
	socklen_t target_len;
	size_t hdr_len;
	if (!udp_parse_addr(
		    &target_sa, &target_len, &hdr_len, ctx->ubuf, nrecv)) {
		/* RFC 1928 section 7 also permits ATYP = DOMAINNAME here,
		 * which this relay does not resolve, so such a datagram is
		 * dropped. */
		SOCKS_CTX_LOG_F(
			DEBUG, ctx,
			"UDP: discarding datagram with an unsupported or truncated address (atyp %" PRIuFAST8
			", %zu bytes)",
			(uint_fast8_t)udph.addrtype, nrecv);
		return;
	}
	udp_send_target(
		loop, ctx, ctx->ubuf + hdr_len, nrecv - hdr_len, &target_sa,
		target_len);
}

static void
tcp_monitor_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_UDP_RELAY);
	/* Any readable event: check for EOF on the TCP control connection */
	unsigned char discard_buf[64];
	ssize_t n;
	do {
		n = recv(ctx->accepted_fd, discard_buf, sizeof(discard_buf), 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return;
		}
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "TCP control: recv: (%d) %s", err,
			strerror(err));
	} else if (n > 0) {
		/* Unexpected data on TCP control connection; ignore */
		ctx->s->stats.byt_client_recv += (uint_least64_t)n;
		return;
	}
	SOCKS_CTX_LOG(VERBOSE, ctx, "UDP ASSOCIATE: TCP control closed");
	gc_unref(&ctx->gcbase);
	(void)loop;
}

static void
socks_udp_start(struct ev_loop *loop, struct socks_ctx *restrict ctx)
{
	ASSERT(ctx->state == STATE_PROCESS);
	const int family = ctx->accepted_sa.sa.sa_family;
	const int udp_fd = socks_open_bound_fd(ctx, family, SOCK_DGRAM);
	if (udp_fd < 0) {
		return;
	}
	ctx->dialed_fd = udp_fd;
	if (!socks5_sendrsp(ctx, SOCKS5RSP_SUCCEEDED)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	SOCKS_CTX_LOG(VERBOSE, ctx, "UDP ASSOCIATE: relay ready");
	struct server_stats *restrict stats = &ctx->s->stats;
	ctx->udp_peer_known = false;
	ctx->udp_ntargets = 0;
	for (size_t i = 0; i < ARRAY_SIZE(ctx->udp_out); i++) {
		ctx->udp_out[i].fd = -1;
		ctx->udp_out[i].failed = false;
	}
	udp_frag_reset(ctx);
	/* Set state before the halfopen decrement below -- ctx_stop is a
	 * no-op if gc_unref fires in between, matching socks_start_transfer/
	 * forward_commit/http_ctx_start_transfer. */
	ctx->state = STATE_UDP_RELAY;
	ev_timer_stop(loop, &ctx->w_timeout);
	stats->num_halfopen--;
	const size_t cur = server_account_session(ctx->s);
	ev_io_init(&ctx->w_udp, udp_client_cb, udp_fd, EV_READ);
	ctx->w_udp.data = ctx;
	ev_io_start(loop, &ctx->w_udp);
	ev_io_init(&ctx->w_tcp, tcp_monitor_cb, ctx->accepted_fd, EV_READ);
	ctx->w_tcp.data = ctx;
	ev_io_start(loop, &ctx->w_tcp);
	/* The reassembly timer is armed on demand by udp_frag_timer_sync() while a
	 * fragment sequence is pending; init with repeat set so ev_timer_again
	 * arms it to SOCKS_UDP_FRAG_TIMEOUT. */
	ev_timer_init(
		&ctx->w_frag, udp_frag_timeout_cb, 0.0, SOCKS_UDP_FRAG_TIMEOUT);
	ctx->w_frag.data = ctx;
	SOCKS_CTX_LOG_F(
		VERBOSE, ctx, "UDP ASSOCIATE: %zu active sessions", cur);
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
		/* The ruleset path routes only TCP CONNECT; conf.c forbids the
		 * flag combination for --ruleset, but a --boot script can
		 * install rules and reach here, so reject BIND/UDP here. */
		if (read_uint8(ctx->rbuf.data) == SOCKS5) {
			struct socks5_hdr h;
			socks5hdr_read(&h, ctx->next);
			if (h.command == SOCKS5CMD_BIND ||
			    h.command == SOCKS5CMD_UDPASSOCIATE) {
				socks5_sendrsp(ctx, SOCKS5RSP_CMDNOSUPPORT);
				gc_unref(&ctx->gcbase);
				return;
			}
		}
		/* other commands route as TCP CONNECT */
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif /* WITH_RULESET */
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
	(void)loop;
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
		} else if (version == SOCKS4) {
			/* SOCKS4 has no TTL-expired code; 91/REJECTED is its
			 * standard failure reply, sent on every other SOCKS4
			 * failure path too */
			socks4_sendrsp(ctx, SOCKS4RSP_REJECTED);
		}
	} break;
	case STATE_BIDIRECTIONAL:
	case STATE_UDP_RELAY:
		return;
	default:
		FAILMSGF("unexpected socks_ctx state: %d", ctx->state);
	}
	ctx->s->stats.num_reject_timeout++;
	gc_unref(&ctx->gcbase);
}

/* send the SOCKS success response and start the transfer; takes ownership of
 * @p fd */
static void socks_commit(
	struct ev_loop *restrict loop, struct socks_ctx *restrict ctx,
	const int fd)
{
	ctx->dialed_fd = fd;
	if (!socks_sendrsp(ctx, true)) {
		gc_unref(&ctx->gcbase);
		return;
	}

	SOCKS_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	/* Any client bytes pipelined after the SOCKS request were never
	 * forwarded upstream; replay them now while both fds are valid. */
	const size_t readahead = ctx->rbuf.len - ctx->reqlen;
	if (readahead > 0 && !forward_readahead(
				     fd, ctx->rbuf.data + ctx->reqlen,
				     readahead, &ctx->s->byt_up)) {
		SOCKS_CTX_LOG(
			WARNING, ctx,
			"failed to forward pipelined bytes to upstream");
		gc_unref(&ctx->gcbase);
		return;
	}
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_socket);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	socks_start_transfer(loop, ctx);
}

static void socks_senderr(
	struct socks_ctx *restrict ctx, const enum dialer_error err,
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

static void dialer_cb(struct ev_loop *restrict loop, void *data, const int fd)
{
	struct socks_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		const enum dialer_error err = ctx->dialer.err;
		const int syserr = ctx->dialer.syserr;
		char errbuf[128];
		SOCKS_CTX_LOG_F(
			ERROR, ctx, "dialer: %s",
			dialer_errorstr(errbuf, sizeof(errbuf), &ctx->dialer));
		ctx->s->stats.num_reject_upstream++;
		socks_senderr(ctx, err, syserr);
		gc_unref(&ctx->gcbase);
		return;
	}
	socks_commit(loop, ctx, fd);
}

#if WITH_RULESET
/* await.forward() commit hook */
static void socks_forward_commit(
	struct ev_loop *restrict loop, struct ruleset_callback *restrict cb,
	const int fd)
{
	struct socks_ctx *restrict ctx = cb->w_finish.data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->ruleset_state = NULL;
	socks_commit(loop, ctx, fd);
}

static void ruleset_cb(
	struct ev_loop *restrict loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct socks_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->dialreq = ctx->ruleset_callback.request.req;
	ctx->ruleset_state = NULL;
	if (ctx->dialreq == NULL) {
		/* the ruleset gave up: reject by policy, which SOCKS5 answers
		 * as "connection not allowed by ruleset" (RFC 1928 section 6) */
		ctx->s->stats.num_reject_ruleset++;
		socks_senderr(ctx, DIALER_ERR_BLOCKED, 0);
		gc_unref(&ctx->gcbase);
		return;
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
	ASSERT(ctx->state == STATE_PROCESS);
	if (ruleset == NULL) {
		if (ctx->s->conf->auth_required) {
			socks_senderr(ctx, DIALER_ERR_BLOCKED, 0);
			gc_unref(&ctx->gcbase);
			return;
		}
		ctx->dialreq = make_dialreq(ctx, &ctx->addr);
		socks_connect(loop, ctx);
		return;
	}

	const struct dialaddr *restrict addr = &ctx->addr;
	/* the binding takes a null-terminated name, which the request parser
	 * guarantees by refusing a domain name carrying a null byte */
	ASSERT(addr->type != ATYP_DOMAIN ||
	       memchr(addr->domain.name, '\0', addr->domain.len) == NULL);
	char request[DIALADDR_STRLEN + 1];
	const int n = dialaddr_format(request, sizeof(request), addr);
	ASSERT(n >= 0 && (size_t)n < sizeof(request));
	const struct ruleset_credentials *restrict creds = &ctx->auth.creds;
	if (LOGLEVEL(VERBOSE)) {
		/* the user name is not null-terminated and may hold any octet
		 * (RFC 1929 section 2) */
		char uname[SOCKS_USERNAME_LOG_STRLEN + 1];
		if (creds->username != NULL) {
			(void)log_escape(
				uname, sizeof(uname), creds->username,
				creds->username_len);
		} else {
			uname[0] = '-';
			uname[1] = '\0';
		}
		char raddr[DIALADDR_LOG_STRLEN + 1];
		(void)log_escape(raddr, sizeof(raddr), request, (size_t)n);
		SOCKS_CTX_LOG_F(
			VERBOSE, ctx, "request: username=`%s' `%s'", uname,
			raddr);
	}
	const bool ok = ruleset_dispatch(
		ruleset, &ctx->ruleset_state, request, addr->type, creds,
		&ctx->ruleset_callback);
	if (!ok) {
		ctx->s->stats.num_reject_ruleset++;
		(void)socks_sendrsp(ctx, false);
		gc_unref(&ctx->gcbase);
		return;
	}
}

/* Release the ruleset work the context still owes. A start that failed may
 * have published its state anyway, and a request that completed in this same
 * loop sweep leaves w_finish pending with a delivered dialreq; neither is tied
 * to a context state, so every path that stops expecting the callback releases
 * both. */
static void
cancel_ruleset(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	if (ctx->ruleset_state != NULL) {
		ruleset_cancel(loop, ctx->ruleset_state);
		ctx->ruleset_state = NULL;
	}
	ruleset_request_cancel(loop, &ctx->ruleset_callback);
}
#endif /* WITH_RULESET */

static void
socks_ctx_stop(struct ev_loop *restrict loop, struct socks_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
#if WITH_RULESET
	/* the union arm holding the ruleset fields is live only here */
	if (ctx->state < STATE_BIDIRECTIONAL) {
		cancel_ruleset(loop, ctx);
	}
#endif /* WITH_RULESET */

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
#endif /* WITH_RULESET */
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
	case STATE_BIDIRECTIONAL:
		/* transfer_ctx is self-owned; nothing to do */
		return;
	case STATE_UDP_RELAY:
		ev_io_stop(loop, &ctx->w_udp);
		ev_io_stop(loop, &ctx->w_tcp);
		ev_timer_stop(loop, &ctx->w_frag);
		for (size_t i = 0; i < ARRAY_SIZE(ctx->udp_out); i++) {
			if (ctx->udp_out[i].fd != -1) {
				ev_io_stop(loop, &ctx->udp_out[i].w_io);
				socket_close(ctx->udp_out[i].fd);
				ctx->udp_out[i].fd = -1;
			}
		}
		server_session_decr(ctx->s);
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

static void socks_ctx_finalize(struct gcbase *restrict obj)
{
	struct socks_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct socks_ctx, gcbase, obj);
	SOCKS_CTX_LOG_F(VERBOSE, ctx, "closing, state=%d", ctx->state);

	socks_ctx_stop(ctx->s->loop, ctx);
	if (ctx->accepted_fd != -1) {
		socket_close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		socket_close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	if (ctx->state < STATE_BIDIRECTIONAL) {
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
	ctx->ruleset_callback.forward = socks_forward_commit;
	ctx->ruleset_state = NULL;
#endif

	ctx->auth.method = SOCKS5AUTH_NOACCEPTABLE;
	ctx->auth.creds = (struct ruleset_credentials){ 0 };
	BUF_INIT(ctx->rbuf, 0);
	ctx->next = ctx->rbuf.data;
	ctx->dialreq = NULL;
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(
		&ctx->dialer, &cb, &ctx->s->stats.byt_dial_send,
		&ctx->s->stats.byt_dial_recv);
	gc_register(&ctx->gcbase, socks_ctx_finalize);
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
		socket_close(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	socks_ctx_start(loop, ctx);
}
