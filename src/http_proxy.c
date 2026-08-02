/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "codec/base64.h"
#include "meta/arraysize.h"
#include "meta/class.h"
#include "net/http.h"
#include "net/url.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/ctype_ascii.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_PROCESS,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_ESTABLISHED,
	STATE_FORWARD,
	/* proxy_pass framing forwarder (full-duplex request/response pumps) */
	STATE_STREAM,
	/* CONNECT raw relay (transfer-engine owned) */
	STATE_BIDIRECTIONAL,
};

struct http_stream;

/* maximum number of forwarded end-to-end headers */
enum { PROXY_MAX_HEADERS = 100 };

struct http_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	ev_timer w_timeout;

	/* Request/dial state. These are NOT storage-shared with `stream` below:
	 * `conn` stays live throughout STATE_STREAM, which proxy_pass reads
	 * while the stream runs. */
	ev_io w_recv, w_send;
#if WITH_RULESET
	ev_idle w_process;
	struct ruleset_callback ruleset_callback;
	struct ruleset_state *ruleset_state;
#endif
	struct dialreq *dialreq;
	struct dialer dialer;
	struct http_conn conn;
	size_t req_content_length;
	/* end-to-end headers recorded for forwarding */
	struct http_header_kv fwd_hdr[PROXY_MAX_HEADERS];
	size_t num_fwd_hdr;
	/* dial target hostport for proxy_pass requests */
	char req_target[DIALADDR_STRLEN + 1];
	bool req_content_length_known : 1;
	/* request switches protocols (Connection: upgrade + Upgrade) and carries
	 * no body: it is forwarded verbatim then relayed raw, so the upstream's
	 * 101 and every post-upgrade byte pass through untouched (see
	 * build_forward_req and send_cb). Enables ws:// through proxy_pass. */
	bool req_upgrade : 1;
	const char *req_upgrade_value; /* client Upgrade value, forwarded as-is */

	/* proxy_pass framing state (state == STATE_STREAM); heap-allocated at
	 * stream start, freed on teardown */
	struct http_stream *stream;
};
ASSERT_SUPER(struct gcbase, struct http_ctx, gcbase);

/* -------------------------------------------------------------------------
 * proxy_pass HTTP/1.1 framing forwarder types (logic follows below)
 * ---------------------------------------------------------------------- */

/* one-directional framing body forwarder: an http_framer (all HTTP framing
 * logic, I/O-free) plus the socket/watcher plumbing that drives it. The
 * response pump also uses framer.in as the receive buffer for the upstream
 * header block before the body starts (see rsp_run / rsp_build_response). */
struct http_pump {
	struct http_stream *owner;
	int src_fd, dst_fd;
	ev_io w;
	struct http_framer framer;
	/* traffic counter for this direction (byt_up for the request pump,
	 * byt_down for the response pump); counts framed bytes sent to dst_fd */
	xfer_counter *byt;
	/* body complete and output flushed; for the response pump the dst write
	 * side is also shut down (see pump_finished) */
	bool done;
};

enum rsp_phase {
	RSP_HDR, /* reading + parsing the upstream response headers */
	RSP_SEND, /* sending the rebuilt response headers to the client */
	RSP_BODY, /* forwarding the response body via the rsp pump */
};

struct http_stream {
	struct http_ctx *ctx;
	struct http_pump req; /* client  -> upstream */
	struct http_pump rsp; /* upstream -> client  */
	/* response header phase state */
	enum rsp_phase rsp_phase;
	struct http_reader rsp_reader; /* incremental parse of rsp.framer.in */
	bool head_request; /* request method was HEAD -> response is bodiless */
	bool rsp_interim; /* the header block just sent was a 1xx interim */
	bool rsp_started; /* at least one response header block reached client */
	struct http_message rsp_msg;
	const char *rsp_connection; /* response Connection header value */
	bool rsp_chunked;
	/* inner (non-chunked) transfer-codings preceding the final "chunked",
	 * forwarded to the client verbatim; NULL for a bare "chunked" */
	const char *rsp_te_prefix;
	bool rsp_clen_known;
	size_t rsp_clen;
	struct http_header_kv rsp_hdr[PROXY_MAX_HEADERS];
	size_t rsp_nhdr;
	size_t whdr_pos; /* client response-header send offset into conn.wbuf */
};

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct http_ctx *restrict ctx)
{
	char caddr[64];
	sa_format(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if (ctx->state < STATE_CONNECT || STATE_FORWARD < ctx->state) {
		return snprintf(
			s, maxlen, "[fd:%d] %s", ctx->accepted_fd, caddr);
	}
	return snprintf(
		s, maxlen, "[fd:%d] %s -> `%s'", ctx->accepted_fd, caddr,
		ctx->conn.msg.req.url);
}

#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
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
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

static void http_ctx_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
		ev_io_stop(loop, &ctx->w_recv);
		stats->num_halfopen--;
		return;
	case STATE_PROCESS:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_process);
		if (ctx->ruleset_state != NULL) {
			ruleset_cancel(loop, ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
		/* a request that completed in this same loop sweep left w_finish
		 * pending with a delivered dialreq; drop it so it cannot fire into
		 * this freed ctx and the dialreq is not leaked */
		ruleset_request_cancel(loop, &ctx->ruleset_callback);
#endif /* WITH_RULESET */
		stats->num_halfopen--;
		return;
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		dialer_cancel(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
	case STATE_FORWARD:
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_STREAM:
		if (ctx->stream != NULL) {
			ev_io_stop(loop, &ctx->stream->req.w);
			ev_io_stop(loop, &ctx->stream->rsp.w);
		}
		server_session_decr(ctx->s);
		return;
	case STATE_BIDIRECTIONAL:
		/* transfer_ctx is self-owned; nothing to do */
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

static void http_ctx_finalize(struct gcbase *restrict obj)
{
	struct http_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct http_ctx, gcbase, obj);
	HTTP_CTX_LOG_F(VERBOSE, ctx, "closing state=%d", ctx->state);

	http_ctx_stop(ctx->s->loop, ctx);
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
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
	}
	free(ctx->stream);
	ctx->stream = NULL;
}

/* Start bidirectional transfer; always calls gc_unref.
 * Caller must stop watchers and release dialreq/cbuf first. */
static void
http_ctx_start_transfer(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/* Set state before transfer_start — ctx_stop is a no-op if gc_unref fires below. */
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen--;
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "transfer start: [%d<->%d]", acc_fd, dial_fd);
	const size_t cur =
		server_commit_session(ctx->s, &ctx->gcbase, acc_fd, dial_fd);
	if (cur == 0) {
		return;
	}
	HTTP_CTX_LOG_F(DEBUG, ctx, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

/* Bytes already buffered past the parsed request/headers (e.g. from a
 * TCP-fast-open client that didn't wait for a reply before sending
 * payload). */
static size_t readahead_len(const struct http_conn *restrict p)
{
	return p->rbuf.len - (size_t)((unsigned char *)p->next - p->rbuf.data);
}

/* Append a string to the connection's write buffer, failing instead of
 * truncating. */
static bool fwd_append(struct http_conn *restrict p, const char *restrict s)
{
	return http_append((struct buffer *)&p->wbuf, s);
}

/* -------------------------------------------------------------------------
 * proxy_pass HTTP/1.1 framing forwarder
 *
 * Replaces the raw relay for proxy_pass: each direction dechunks its input and
 * re-chunks (or length-forwards) its output through a bounded buffer, so
 * per-connection memory stays capped and message framing is validated end to
 * end. Full-duplex: the request and response pumps run concurrently (required
 * for Expect: 100-continue and early upstream responses). CONNECT keeps the
 * raw relay. No keep-alive: the connection closes once both directions finish.
 * ---------------------------------------------------------------------- */

/* Point a pump's single watcher at src(read) or dst(write). */
static void
pump_watch(struct ev_loop *loop, struct http_pump *restrict p, const int events)
{
	const int fd = (events & EV_WRITE) ? p->dst_fd : p->src_fd;
	if (p->w.fd == fd && (p->w.events & (EV_READ | EV_WRITE)) == events) {
		return;
	}
	ev_io_stop(loop, &p->w);
	ev_io_set(&p->w, fd, events);
	ev_io_start(loop, &p->w);
}

/* Tear down the whole connection (single owner reference). Callers must not
 * touch the ctx/stream after this returns. */
static void stream_close(struct ev_loop *loop, struct http_stream *restrict s)
{
	(void)loop;
	gc_unref(&s->ctx->gcbase);
}

/* Rearm the idle timeout on stream activity while the exchange is still being
 * established (forwarding the request, waiting for the response). Once the
 * response body is streaming (RSP_BODY) the timeout is released and never
 * rearmed here, because a response body may idle legitimately for long
 * periods (SSE, long-poll, streaming); a dead peer is then caught by TCP
 * keepalive, exactly as for a CONNECT tunnel. */
static void stream_touch(struct ev_loop *loop, struct http_stream *restrict s)
{
	if (s->rsp_phase != RSP_BODY) {
		ev_timer_again(loop, &s->ctx->w_timeout);
	}
}

/* Fail the stream: if no response byte has reached the client yet, send a
 * best-effort error page (@p code) before closing; otherwise just close. */
static void stream_fail(
	struct ev_loop *loop, struct http_stream *restrict s,
	const uint_fast16_t code)
{
	if (!s->rsp_started) {
		struct http_conn *restrict conn = &s->ctx->conn;
		http_resp_errpage(conn, code);
		/* best-effort synchronous write -- the connection is closing */
		size_t off = 0;
		while (off < conn->wbuf.len) {
			size_t n = conn->wbuf.len - off;
			const int err = socket_send(
				s->ctx->accepted_fd, conn->wbuf.data + off, &n);
			if (err != 0 || n == 0) {
				break;
			}
			off += n;
		}
		/* This page replaces the response headers the pump would have
		 * sent, on the same socket in the same phase, so it belongs to
		 * the same counter the pump would have used -- off is exactly
		 * what reached the wire, since a failed send breaks out without
		 * advancing it. */
		xfer_count(&s->ctx->s->byt_down, off);
	}
	stream_close(loop, s);
}

/* A pump's body is complete and its output flushed: shut its write side (so
 * the peer sees end-of-message) and, once both directions are done, close. */
static void pump_finished(struct ev_loop *loop, struct http_pump *restrict p)
{
	struct http_stream *restrict s = p->owner;
	ev_io_stop(loop, &p->w);
	/* Only the response pump half-closes: without keep-alive the FIN signals
	 * response completion. A request body is self-delimited (RFC 9112 §6.3),
	 * so an early FIN on the request direction is unnecessary and harmful. */
	if (p == &s->rsp) {
		(void)socket_shutdown(p->dst_fd, SHUT_WR);
	}
	p->done = true;
	if (s->req.done && s->rsp.done) {
		HTTP_CTX_LOG(DEBUG, s->ctx, "stream complete");
		stream_close(loop, s);
	}
}

/* Drive one framing pump as far as it can go without blocking. All body framing
 * lives in the http_framer; this shell only decides when to touch a socket. */
static void
pump_run(struct ev_loop *restrict loop, struct http_pump *restrict p)
{
	struct http_framer *restrict f = &p->framer;
	for (;;) {
		switch (http_framer_run(f)) {
		case HTTP_FRAMER_SEND: {
			const unsigned char *buf;
			size_t n = http_framer_pending(f, &buf);
			const int err = socket_send(p->dst_fd, buf, &n);
			if (err != 0) {
				if (err == EAGAIN || err == EWOULDBLOCK ||
				    err == ENOBUFS || err == ENOMEM) {
					pump_watch(loop, p, EV_WRITE);
					return;
				}
				stream_close(loop, p->owner);
				return;
			}
			http_framer_drained(f, n);
			xfer_count(p->byt, n);
			stream_touch(loop, p->owner);
			if (http_framer_pending(f, &buf) > 0) {
				pump_watch(loop, p, EV_WRITE);
				return;
			}
			continue;
		}
		case HTTP_FRAMER_FILL: {
			unsigned char *buf;
			size_t n;
			http_framer_inbuf(f, &buf, &n);
			const int err = socket_recv(p->src_fd, buf, &n);
			if (err != 0) {
				if (err == EAGAIN || err == EWOULDBLOCK) {
					pump_watch(loop, p, EV_READ);
					return;
				}
				stream_close(loop, p->owner);
				return;
			}
			if (n == 0) {
				if (!http_framer_eof(f)) {
					stream_close(loop, p->owner);
					return;
				}
				continue;
			}
			http_framer_filled(f, n);
			stream_touch(loop, p->owner);
			continue;
		}
		case HTTP_FRAMER_DONE:
			pump_finished(loop, p);
			return;
		case HTTP_FRAMER_ERROR: {
			HTTP_CTX_LOG(WARNING, p->owner->ctx, "malformed body");
			const bool is_request = (p == &p->owner->req);
			stream_fail(
				loop, p->owner,
				is_request ? HTTP_BAD_REQUEST :
					     HTTP_BAD_GATEWAY);
			return;
		}
		}
		/* no default: -Wswitch guards new enumerators; unreachable here */
		FAILMSG("unexpected http_framer op");
	}
}

static void pump_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	pump_run(loop, watcher->data);
}

/* True if any comma-separated transfer-coding in the (non-empty) list is
 * "chunked", used to reject a response that applies chunked more than once or
 * not as the final coding (RFC 9112 §6.1). Scans without modifying the string. */
static bool te_list_has_chunked(const char *restrict list)
{
	for (const char *tok = list; tok != NULL;) {
		const char *const comma = strchr(tok, ',');
		const char *end = (comma != NULL) ? comma : tok + strlen(tok);
		while (tok < end && isspace((unsigned char)*tok)) {
			tok++;
		}
		while (end > tok && isspace((unsigned char)end[-1])) {
			end--;
		}
		const size_t len = (size_t)(end - tok);
		if (len == sizeof("chunked") - 1 &&
		    strncasecmp(tok, "chunked", len) == 0) {
			return true;
		}
		tok = (comma != NULL) ? comma + 1 : NULL;
	}
	return false;
}

/* Record one response header for forwarding, or capture the framing/hop-by-hop
 * headers we handle specially. Returns false to reject the whole response (bad
 * header characters, a malformed Content-Length, or header-table overflow),
 * which the caller maps to 502. */
static bool rsp_record_header(void *ctx, const char *key, char *value)
{
	struct http_stream *restrict s = ctx;
	if (!http_header_field_valid(key, value)) {
		return false;
	}
	if (strcasecmp(key, "Connection") == 0) {
		s->rsp_connection = value;
		return true;
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		/* RFC 9110 §5.2 / 9112 §6.1: repeated field lines are a
		 * comma-joined value and chunked applies at most once, so a second
		 * Transfer-Encoding: chunked line is the same violation as
		 * "chunked, chunked" on one line (rejected below), mirroring the
		 * Content-Length duplicate guard. */
		if (s->rsp_chunked) {
			return false;
		}
		/* RFC 9112 §6.1: the response body may carry a stack of transfer
		 * codings terminated by "chunked" (e.g. "gzip, chunked"). The
		 * final coding must be chunked -- any other framing cannot be
		 * delimited, so reject it rather than drop the header and
		 * mis-frame the body. The inner (non-chunked) codings are opaque:
		 * the framer dechunks then re-chunks the body below, and they are
		 * re-emitted verbatim ahead of chunked so the client can decode
		 * them. */
		char *const te = strtrimspace(value);
		char *const last_comma = strrchr(te, ',');
		const char *const final_coding =
			(last_comma != NULL) ? strtrimspace(last_comma + 1) :
					       te;
		if (strcasecmp(final_coding, "chunked") != 0) {
			return false;
		}
		/* RFC 9112 §6.3: reject TE:chunked conflicting with Content-Length,
		 * mirroring the request side */
		if (s->rsp_clen_known) {
			return false;
		}
		if (last_comma != NULL) {
			*last_comma = '\0';
			char *const prefix = strtrimspace(te);
			/* RFC 9112 §6.1: chunked applies at most once and only as
			 * the final coding; an empty prefix coding is malformed */
			if (prefix[0] == '\0' || te_list_has_chunked(prefix)) {
				return false;
			}
			s->rsp_te_prefix = prefix;
		}
		s->rsp_chunked = true;
		return true;
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		/* RFC 9112 §6.3: reject duplicate CL or CL+TE:chunked conflict */
		if (s->rsp_clen_known || s->rsp_chunked) {
			return false;
		}
		if (!http_parse_content_length(value, &s->rsp_clen)) {
			return false;
		}
		s->rsp_clen_known = true;
		return true;
	}
	if (strcasecmp(key, "Keep-Alive") == 0 || strcasecmp(key, "TE") == 0 ||
	    strcasecmp(key, "Trailer") == 0 ||
	    strcasecmp(key, "Upgrade") == 0 ||
	    strcasecmp(key, "Proxy-Connection") == 0) {
		return true; /* hop-by-hop: never forwarded */
	}
	/* Overflow is fatal, matching the request side, rather than silently
	 * dropping a header (e.g. the 101st Set-Cookie) from the response. */
	if (s->rsp_nhdr >= ARRAY_SIZE(s->rsp_hdr)) {
		return false;
	}
	s->rsp_hdr[s->rsp_nhdr].key = key;
	s->rsp_hdr[s->rsp_nhdr].value = value;
	s->rsp_nhdr++;
	return true;
}

/* Parse the upstream response status line + headers accumulated in rsp.framer.in
 * via the shared incremental reader. Returns 0 when complete (rsp_reader.pos
 * points at the body start), 1 if more data is needed, or -1 on a parse error
 * (a malformed line/header or a header rejected by rsp_record_header). */
static int rsp_parse_headers(struct http_stream *restrict s)
{
	const struct http_parsehdr_cb on_header = {
		.func = rsp_record_header,
		.ctx = s,
	};
	switch (http_reader_parse(
		&s->rsp_reader, (char *)s->rsp.framer.in, &s->rsp_msg, false,
		on_header)) {
	case HTTP_READER_OK:
		return 0;
	case HTTP_READER_MORE:
		return 1;
	case HTTP_READER_ERROR:
		return -1;
	}
	FAILMSG("unexpected http_reader state");
}

/* RFC 9112 §4: status-code = 3DIGIT. http_parse only splits the status line on
 * spaces, so an upstream code reaching here is not yet known to be numeric. */
static bool status_code_valid(const char *restrict s)
{
	size_t n;
	for (n = 0; s[n] != '\0'; n++) {
		if (!isdigit((unsigned char)s[n])) {
			return false;
		}
	}
	return n == 3;
}

/* Emit a canonical interim (1xx) response to the client, then keep reading. */
static bool rsp_build_interim(struct http_stream *restrict s)
{
	struct http_conn *restrict conn = &s->ctx->conn;
	conn->wbuf.len = 0;
	s->whdr_pos = 0;
	/* http_parse validates neither the code nor the reason phrase, so guard
	 * the client-facing status line as rsp_build_response does for the final
	 * one. A 502 cannot replace an interim (the final response may still be
	 * coming, and an earlier interim may already be on the wire), so drop a
	 * malformed interim -- emit nothing, read on -- rather than inject an
	 * unvalidated code (with possible control bytes) into the status line. */
	if (!status_code_valid(s->rsp_msg.rsp.code)) {
		HTTP_CTX_LOG(
			WARNING, s->ctx,
			"malformed interim response status code, dropping");
		return true;
	}
	struct buffer *restrict wbuf = (struct buffer *)&conn->wbuf;
	const char *const status = http_status(
		(uint_fast16_t)strtoul(s->rsp_msg.rsp.code, NULL, 10));
	/* forward the interim's end-to-end headers (e.g. Link: on 103 Early
	 * Hints, whose headers are the whole point of the response) */
	return fwd_append(conn, "HTTP/1.1 ") &&
	       fwd_append(conn, s->rsp_msg.rsp.code) && fwd_append(conn, " ") &&
	       fwd_append(conn, status != NULL ? status : "") &&
	       fwd_append(conn, "\r\n") &&
	       http_append_headers(
		       wbuf, s->rsp_hdr, s->rsp_nhdr, s->rsp_connection) &&
	       /* RFC 9110 §7.6.3: add our Via entry to the forwarded interim too
		* (received-protocol = upstream response version, past "HTTP/") */
	       fwd_append(conn, "Via: ") &&
	       fwd_append(conn, s->rsp_msg.rsp.version + 5) &&
	       fwd_append(conn, " neosocksd\r\n") && fwd_append(conn, "\r\n");
}

/* True when the client request is HTTP/1.0. The request line stays live through
 * STATE_STREAM (see struct http_ctx.conn) and its version was validated by the
 * request parser, so a bare strcmp is enough. */
static bool rsp_client_is_http_1_0(const struct http_stream *restrict s)
{
	return strcmp(s->ctx->conn.msg.req.version, "HTTP/1.0") == 0;
}

/* Rebuild the final response headers for the client into conn.wbuf and decide
 * the response body framing. */
static bool rsp_build_response(struct http_stream *restrict s)
{
	struct http_conn *restrict conn = &s->ctx->conn;
	conn->wbuf.len = 0;
	s->whdr_pos = 0;
	/* http_parse validates neither the code nor the reason phrase, so a
	 * broken or hostile upstream could otherwise put a non-numeric code or
	 * control bytes into the client-facing status line -- inconsistent with
	 * the response headers, which are rejected for CTLs. Fail a malformed
	 * code (the caller turns that into a 502) and re-emit the canonical
	 * reason instead of the upstream's, exactly as rsp_build_interim does.
	 * RFC 9112 §4 makes the reason phrase advisory, so nothing is lost. */
	if (!status_code_valid(s->rsp_msg.rsp.code)) {
		HTTP_CTX_LOG(WARNING, s->ctx, "malformed response status code");
		return false;
	}
	const unsigned long code = strtoul(s->rsp_msg.rsp.code, NULL, 10);
	const char *const status = http_status((uint_fast16_t)code);

	struct buffer *restrict wbuf = (struct buffer *)&conn->wbuf;
	bool ok = fwd_append(conn, "HTTP/1.1 ") &&
		  fwd_append(conn, s->rsp_msg.rsp.code) &&
		  fwd_append(conn, " ") &&
		  fwd_append(conn, status != NULL ? status : "") &&
		  fwd_append(conn, "\r\n");
	/* end-to-end headers, except those listed in Connection */
	ok = ok && http_append_headers(
			   wbuf, s->rsp_hdr, s->rsp_nhdr, s->rsp_connection);
	/* RFC 9110 §7.6.3: a proxy MUST add a Via entry to every message it
	 * forwards, both directions; the response side mirrors what
	 * build_forward_req() does for the request. The received-protocol names
	 * the upstream response version (validated to start with "HTTP/", so
	 * skip that 5-char prefix). */
	ok = ok && fwd_append(conn, "Via: ") &&
	     fwd_append(conn, s->rsp_msg.rsp.version + 5) &&
	     fwd_append(conn, " neosocksd\r\n");
	/* Preserve the declared framing header even for a bodiless response
	 * (e.g. a HEAD reply keeps its Content-Length); only the body is
	 * suppressed below. */
	const bool bodiless = s->head_request || code == 204 || code == 304;
	/* RFC 9112 §6.1: an HTTP/1.0 client cannot parse chunked framing, so never
	 * send it Transfer-Encoding; forward a known length, else deliver the body
	 * EOF-delimited (the Connection: close above bounds it). */
	const bool client_1_0 = rsp_client_is_http_1_0(s);
	if (client_1_0 && s->rsp_te_prefix != NULL && !bodiless) {
		/* The framer only strips the final "chunked": the inner codings
		 * stay applied to the forwarded octets, and the only way to tell
		 * the client about them is a Transfer-Encoding header, which the
		 * branch below must not send to a 1.0 client. Delivering them as
		 * identity content would hand it undecodable bytes it has no way
		 * to know are encoded, so refuse the combination the way an
		 * unsupported final coding already is. (A bodiless response --
		 * HEAD, 204, 304 -- carries no such octets and falls through.) */
		HTTP_CTX_LOG(
			WARNING, s->ctx,
			"HTTP/1.0 client cannot be told about the response's inner transfer-codings");
		return false;
	}
	if (client_1_0) {
		ok = ok && http_append_framing(
				   wbuf, false, s->rsp_clen_known, s->rsp_clen);
	} else if (s->rsp_te_prefix != NULL) {
		/* re-emit the inner codings ahead of the chunked framing the
		 * response pump regenerates for the forwarded opaque bytes */
		ok = ok && fwd_append(conn, "Transfer-Encoding: ") &&
		     fwd_append(conn, s->rsp_te_prefix) &&
		     fwd_append(conn, ", chunked\r\n");
	} else {
		ok = ok && http_append_framing(
				   wbuf, s->rsp_chunked, s->rsp_clen_known,
				   s->rsp_clen);
	}
	/* the upstream Connection/Keep-Alive headers were dropped above;
	 * overwrite the client-facing connection disposition to close (no
	 * keep-alive) since the connection is torn down after this response */
	ok = ok && fwd_append(conn, "Connection: close\r\n\r\n");
	if (!ok) {
		return false;
	}

	/* set up the response body pump */
	struct http_pump *restrict rsp = &s->rsp;
	enum http_body_mode mode;
	size_t clen = 0;
	if (bodiless) {
		mode = HTTP_BODY_NONE;
	} else if (s->rsp_chunked) {
		mode = HTTP_BODY_CHUNKED;
	} else if (s->rsp_clen_known) {
		mode = HTTP_BODY_CONTENT_LENGTH;
		clen = s->rsp_clen;
	} else {
		mode = HTTP_BODY_EOF; /* close-delimited */
	}
	/* framer.in still holds the bytes read during RSP_HDR; the header block
	 * ends at rsp_reader.pos, so seed the filter with [pos, in_len) as the
	 * start of the body (init resets in_len, so capture it first) */
	const size_t buffered = rsp->framer.in_len;
	/* dechunk the upstream body but do not re-chunk it for a 1.0 client (no TE
	 * header was emitted); the dechunked bytes go out EOF-delimited */
	const bool rechunk = (mode == HTTP_BODY_CHUNKED) && !client_1_0;
	http_framer_init(&rsp->framer, mode, clen, rechunk);
	http_framer_seed(&rsp->framer, s->rsp_reader.pos, buffered);
	return true;
}

/* Discard the just-parsed interim (1xx) header block at the front of
 * rsp.framer.in and reset every per-response framing/hop-by-hop field, so the
 * next response parses fresh from the buffer start. Shared by the two interim
 * paths: after an interim is forwarded to the client, and when one is dropped
 * unsent because the client is HTTP/1.0 (RFC 9110 §15.2). */
static void rsp_drop_interim(struct http_stream *restrict s)
{
	struct http_pump *restrict rsp = &s->rsp;
	/* reset every framing/hop-by-hop field rsp_record_header may have set
	 * from the interim's headers, else e.g. a Transfer-Encoding: chunked on
	 * a 1xx would make the following final response be dechunked and
	 * misparsed. */
	s->rsp_chunked = false;
	s->rsp_te_prefix = NULL;
	s->rsp_clen_known = false;
	s->rsp_clen = 0;
	s->rsp_connection = NULL;
	/* drop the interim bytes [0, pos) and keep the trailing bytes, which are
	 * the start of the next response */
	const size_t rest = rsp->framer.in_len - s->rsp_reader.pos;
	memmove(rsp->framer.in, rsp->framer.in + s->rsp_reader.pos, rest);
	rsp->framer.in_len = rest;
	rsp->framer.in[rest] = '\0';
	/* reset the reader (pos=0, line_done=false) to parse the next response
	 * from the front of the buffer */
	http_reader_init(&s->rsp_reader);
	s->rsp_nhdr = 0;
}

/* Response-direction driver: read + parse upstream headers, forward interim
 * (1xx) responses, then stream the body. The RSP_HDR/RSP_SEND/RSP_BODY phase
 * machine runs as a loop, so a burst of pipelined interim responses iterates
 * rather than recursing one stack frame per interim. */
static void
rsp_run(struct ev_loop *restrict loop, struct http_stream *restrict s)
{
	struct http_pump *restrict rsp = &s->rsp;
	struct http_conn *restrict conn = &s->ctx->conn;
	for (;;) {
		switch (s->rsp_phase) {
		case RSP_HDR: {
			const int r = rsp_parse_headers(s);
			if (r < 0) {
				HTTP_CTX_LOG(
					WARNING, s->ctx,
					"bad upstream response");
				stream_fail(loop, s, HTTP_BAD_GATEWAY);
				return;
			}
			if (r == 0) {
				const unsigned long code =
					strtoul(s->rsp_msg.rsp.code, NULL, 10);
				const bool interim =
					(100 <= code && code < 200);
				/* RFC 9110 §15.2: a 1xx response MUST NOT be
				 * sent to an HTTP/1.0 client, which has no 1xx
				 * concept. Drop the interim header block unsent
				 * and keep reading for the final response. */
				if (interim && rsp_client_is_http_1_0(s)) {
					rsp_drop_interim(s);
					continue;
				}
				const bool ok = interim ? rsp_build_interim(s) :
							  rsp_build_response(s);
				if (!ok) {
					stream_fail(loop, s, HTTP_BAD_GATEWAY);
					return;
				}
				s->rsp_interim = interim;
				s->rsp_phase = RSP_SEND;
				continue;
			}
			if (rsp->framer.in_len + 1 >= sizeof(rsp->framer.in)) {
				HTTP_CTX_LOG(
					WARNING, s->ctx,
					"response headers too large");
				stream_fail(loop, s, HTTP_BAD_GATEWAY);
				return;
			}
			size_t n =
				sizeof(rsp->framer.in) - rsp->framer.in_len - 1;
			const int err = socket_recv(
				rsp->src_fd,
				rsp->framer.in + rsp->framer.in_len, &n);
			if (err != 0) {
				if (err == EAGAIN || err == EWOULDBLOCK) {
					pump_watch(loop, rsp, EV_READ);
					return;
				}
				stream_close(loop, s);
				return;
			}
			if (n == 0) {
				HTTP_CTX_LOG(
					WARNING, s->ctx,
					"upstream closed early");
				stream_fail(loop, s, HTTP_BAD_GATEWAY);
				return;
			}
			stream_touch(loop, s);
			rsp->framer.in_len += n;
			rsp->framer.in[rsp->framer.in_len] = '\0';
			continue;
		}
		case RSP_SEND: {
			while (s->whdr_pos < conn->wbuf.len) {
				size_t n = conn->wbuf.len - s->whdr_pos;
				const int err = socket_send(
					rsp->dst_fd,
					conn->wbuf.data + s->whdr_pos, &n);
				if (err != 0) {
					if (err == EAGAIN ||
					    err == EWOULDBLOCK ||
					    err == ENOBUFS || err == ENOMEM) {
						pump_watch(loop, rsp, EV_WRITE);
						return;
					}
					stream_close(loop, s);
					return;
				}
				xfer_count(rsp->byt, n);
				stream_touch(loop, s);
				s->whdr_pos += n;
				/* Once any header byte is on the wire a later
				 * failure can no longer prepend a clean error
				 * page, so mark the response started immediately
				 * -- not only after the whole block flushes, which
				 * left a mid-block backpressure window where
				 * stream_fail would append an error page after the
				 * partial header the client already received. A
				 * dropped malformed interim writes nothing
				 * (wbuf.len == 0), never enters this loop, and so
				 * correctly leaves rsp_started untouched. */
				s->rsp_started = true;
			}
			if (s->rsp_interim) {
				/* drop the forwarded interim and parse the next
				 * response from the front of the buffer */
				s->rsp_interim = false;
				rsp_drop_interim(s);
				s->rsp_phase = RSP_HDR;
				continue;
			}
			/* The response is committed: release the idle timeout so
			 * a long-lived response stream (SSE, long-poll, streaming
			 * download) is never killed during a legitimate quiet
			 * period. A dead peer is caught by TCP keepalive from here
			 * on, exactly as for an established CONNECT tunnel. */
			ev_timer_stop(loop, &s->ctx->w_timeout);
			s->rsp_phase = RSP_BODY;
			continue;
		}
		case RSP_BODY:
			pump_run(loop, rsp);
			return;
		}
		FAILMSGF("unexpected rsp phase: %d", s->rsp_phase);
	}
}

static void rsp_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct http_pump *restrict rsp = watcher->data;
	rsp_run(loop, rsp->owner);
}

/* Enter the full-duplex framing phase for a proxy_pass request. Takes over the
 * readahead request-body bytes; both fds stay owned by the ctx. */
static void
http_ctx_start_stream(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_stream *restrict s = malloc(sizeof(struct http_stream));
	if (s == NULL) {
		LOGOOM();
		gc_unref(&ctx->gcbase);
		return;
	}
	*s = (struct http_stream){ .ctx = ctx, .rsp_phase = RSP_HDR };
	ctx->stream = s;

	struct http_conn *restrict conn = &ctx->conn;
	const int client_fd = ctx->accepted_fd, upstream_fd = ctx->dialed_fd;
	s->head_request = (strcmp(conn->msg.req.method, "HEAD") == 0);

	/* request pump: client -> upstream, seeded with the readahead body */
	struct http_pump *restrict req = &s->req;
	req->owner = s;
	req->src_fd = client_fd;
	req->dst_fd = upstream_fd;
	req->byt = &ctx->s->byt_up;
	enum http_body_mode reqmode;
	size_t reqclen = 0;
	if (conn->hdr.transfer.encoding == TENCODING_CHUNKED) {
		reqmode = HTTP_BODY_CHUNKED;
	} else if (ctx->req_content_length_known) {
		reqmode = HTTP_BODY_CONTENT_LENGTH;
		reqclen = ctx->req_content_length;
	} else {
		reqmode = HTTP_BODY_NONE;
	}
	http_framer_init(
		&req->framer, reqmode, reqclen, reqmode == HTTP_BODY_CHUNKED);
	const size_t readahead = readahead_len(conn);
	if (readahead > 0) {
		memcpy(req->framer.in, conn->next, readahead);
		http_framer_seed(&req->framer, 0, readahead);
	}
	ev_io_init(&req->w, pump_cb, upstream_fd, EV_WRITE);
	req->w.data = req;

	/* response pump: upstream -> client, headers first */
	struct http_pump *restrict rsp = &s->rsp;
	rsp->owner = s;
	rsp->src_fd = upstream_fd;
	rsp->dst_fd = client_fd;
	rsp->byt = &ctx->s->byt_down;
	ev_io_init(&rsp->w, rsp_cb, upstream_fd, EV_READ);
	rsp->w.data = rsp;

	/* conn.rbuf/wbuf are free now: the readahead was copied out and the
	 * request headers were fully sent. wbuf is reused for the response. */
	VBUF_FREE(conn->cbuf);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	struct server_stats *restrict stats = &ctx->s->stats;
	ctx->state = STATE_STREAM;
	/* Repurpose the handshake deadline as an inactivity timeout that bounds
	 * only the establishment of the exchange -- forwarding the request and
	 * waiting for the response headers. It is rearmed on every byte moved
	 * (stream_touch) and released once the response body starts streaming
	 * (see rsp_run), so a legitimately idle response stream is never
	 * killed. Give it a repeat interval and (re)arm it. */
	ctx->w_timeout.repeat = ctx->s->conf->timeout;
	ev_timer_again(loop, &ctx->w_timeout);
	stats->num_halfopen--;
	(void)server_account_session(ctx->s);
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "stream start: [%d<->%d]", client_fd, upstream_fd);

	ev_io_start(loop, &req->w);
	ev_io_start(loop, &rsp->w);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE ||
	       ctx->state == STATE_ESTABLISHED || ctx->state == STATE_FORWARD);

	int err = 0;
	const int ret = http_conn_send(&ctx->conn, watcher->fd, &err);
	if (ret < 0) {
		HTTP_CTX_LOG_F(
			WARNING, ctx, "socket_send: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ret > 0) {
		return;
	}
	switch (ctx->state) {
	case STATE_ESTABLISHED: {
		/* CONNECT 200 fully sent: a CONNECT tunnel has no cbuf salvage
		 * step, so replay any pipelined client bytes to the upstream now,
		 * while both fds are still valid, then start the raw relay. */
		ev_io_stop(loop, &ctx->w_send);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		const size_t readahead = readahead_len(&ctx->conn);
		if (readahead > 0 && !forward_readahead(
					     ctx->dialed_fd, ctx->conn.next,
					     readahead, &ctx->s->byt_up)) {
			HTTP_CTX_LOG(
				WARNING, ctx,
				"failed to forward pipelined bytes to upstream");
			gc_unref(&ctx->gcbase);
			return;
		}
		VBUF_FREE(ctx->conn.cbuf);
		http_ctx_start_transfer(loop, ctx);
		return;
	}
	case STATE_FORWARD:
		ev_io_stop(loop, &ctx->w_send);
		if (ctx->req_upgrade) {
			/* WebSocket/Upgrade: the rewritten request has reached the
			 * upstream. Hand both directions to the raw relay (as for
			 * CONNECT) so the 101 response and every post-upgrade byte
			 * pass through untouched. Replay any pipelined client bytes
			 * to the upstream first, while both fds are still owned
			 * here, then release dialreq/cbuf as start_stream would. */
			dialreq_free(ctx->dialreq);
			ctx->dialreq = NULL;
			const size_t readahead = readahead_len(&ctx->conn);
			if (readahead > 0 &&
			    !forward_readahead(
				    ctx->dialed_fd, ctx->conn.next, readahead,
				    &ctx->s->byt_up)) {
				HTTP_CTX_LOG(
					WARNING, ctx,
					"failed to forward pipelined bytes to upstream");
				gc_unref(&ctx->gcbase);
				return;
			}
			VBUF_FREE(ctx->conn.cbuf);
			http_ctx_start_transfer(loop, ctx);
			return;
		}
		/* proxy_pass request headers fully sent: enter the framing
		 * forwarder. It takes over the readahead body and frees
		 * cbuf/dialreq itself. */
		http_ctx_start_stream(loop, ctx);
		return;
	case STATE_RESPONSE:
		/* a locally-generated response (error page) was fully sent */
		gc_unref(&ctx->gcbase);
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

/* After a successful dial for a proxy_pass request, wire w_send to the
 * upstream fd and start draining the buffered forwarded request. */
static void
http_ctx_forward(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->state = STATE_FORWARD;
	/* conn now writes the rebuilt request to the upstream rather than to the
	 * client, so its send accounting moves to the upstream-facing counter */
	ctx->conn.byt_sent = &ctx->s->stats.byt_dial_send;
	ev_io_init(&ctx->w_send, send_cb, ctx->dialed_fd, EV_WRITE);
	ctx->w_send.data = ctx;
	ev_io_start(loop, &ctx->w_send);
}

/* commit a connected upstream: for CONNECT queue the 200 response, otherwise
 * replay the buffered request to the upstream; takes ownership of @p fd */
static void
http_commit(struct ev_loop *loop, struct http_ctx *restrict ctx, const int fd)
{
	HTTP_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	ctx->dialed_fd = fd;

	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		/* CONNECT tunnel: queue the 200 response */
		ASSERT(ctx->conn.wbuf.len == 0);
		BUF_APPENDSTR(
			ctx->conn.wbuf,
			"HTTP/1.1 200 Connection established\r\n\r\n");
		ctx->state = STATE_ESTABLISHED;
		ev_io_start(loop, &ctx->w_send);
		return;
	}
	/* plain HTTP: forward the buffered request to upstream */
	http_ctx_forward(loop, ctx);
}

static void send_response(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->state = STATE_RESPONSE;
	ev_io_start(loop, &ctx->w_send);
}

static void send_errpage(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	const uint_fast16_t code)
{
	ASSERT(4 <= (code / 100) && (code / 100) <= 5);
	http_resp_errpage(&ctx->conn, code);
	send_response(loop, ctx);
}

static void http_connect(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* every caller resolves ctx->dialreq (and its error code) first */
	ASSERT(ctx->dialreq != NULL);
	HTTP_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(
		&ctx->dialer, loop, ctx->dialreq, ctx->s->conf,
		ctx->s->resolver, ctx->s);
}

#if WITH_RULESET
static void
ruleset_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->dialreq = ctx->ruleset_callback.request.req;
	ctx->ruleset_state = NULL;
	if (ctx->dialreq == NULL) {
		/* the ruleset gave up: reject by policy (403) */
		ctx->s->stats.num_reject_ruleset++;
		send_errpage(loop, ctx, HTTP_FORBIDDEN);
		return;
	}
	http_connect(loop, ctx);
}

/* await.forward() commit hook */
static void http_forward_commit(
	struct ev_loop *loop, struct ruleset_callback *restrict cb,
	const int fd)
{
	struct http_ctx *restrict ctx = cb->w_finish.data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->ruleset_state = NULL;
	http_commit(loop, ctx, fd);
}

static void parse_proxy_auth(
	unsigned char *buf, const size_t bufsize, const char **username,
	const char **password, const char *authtype, const char *credentials)
{
	if (authtype == NULL || credentials == NULL) {
		return;
	}
	if (strcmp(authtype, "Basic") != 0) {
		return;
	}
	size_t dstlen = bufsize - 1;
	if (!base64_decode(
		    buf, &dstlen, (const unsigned char *)credentials,
		    strlen(credentials))) {
		return;
	}
	char *const s = (char *)buf;
	s[dstlen] = '\0';
	char *const sep = strchr(s, ':');
	if (sep == NULL) {
		return;
	}
	*sep = '\0';
	*username = s;
	*password = sep + 1;
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct http_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);
	ASSERT(ctx->state == STATE_PROCESS);

	unsigned char buf[512];
	const char *username = NULL;
	const char *password = NULL;
	parse_proxy_auth(
		buf, sizeof(buf), &username, &password,
		ctx->conn.hdr.proxy_authorization.type,
		ctx->conn.hdr.proxy_authorization.credentials);
	if (ctx->s->conf->auth_required &&
	    (username == NULL || password == NULL)) {
		RESPHDR_BEGIN(
			ctx->conn.wbuf, HTTP_PROXY_AUTHENTICATION_REQUIRED);
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
		BUF_APPENDSTR(
			ctx->conn.wbuf,
			"Proxy-Authenticate: Basic realm=\"proxy\"\r\n");
		RESPHDR_FINISH(ctx->conn.wbuf);
		send_response(loop, ctx);
		return;
	}

	const char *addr_str;
	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		addr_str = ctx->conn.msg.req.url;
	} else {
		/* filled by build_forward_req() before w_process was started */
		ASSERT(ctx->req_target[0] != '\0');
		addr_str = ctx->req_target;
	}
	const bool ok = ruleset_resolve(
		ruleset, &ctx->ruleset_state, addr_str, username, password,
		&ctx->ruleset_callback);
	if (!ok) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}
#endif /* WITH_RULESET */

/* Rebuild the client request headers in wbuf for forwarding to the upstream
 * and normalize the dial target into ctx->req_target. The body is left in the
 * read buffer for the framing forwarder. Returns 0 on success or an HTTP
 * status on failure. */
static uint_fast16_t build_forward_req(struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	const char *const method = p->msg.req.method;
	const char *const version = p->msg.req.version;

	/* RFC 9112 §3.2.2: a proxy accepts absolute-form only */
	const size_t urllen = strlen(p->msg.req.url);
	ASSERT(urllen < HTTP_MAX_ENTITY);
	char urlbuf[urllen + 1];
	memcpy(urlbuf, p->msg.req.url, urllen + 1);
	struct url parsed;
	if (!url_parse(urlbuf, &parsed) || parsed.scheme == NULL ||
	    strcmp(parsed.scheme, "http") != 0 || parsed.host == NULL ||
	    parsed.host[0] == '\0') {
		return HTTP_BAD_REQUEST;
	}
	if (!http_hostport_normalize(
		    ctx->req_target, sizeof(ctx->req_target), parsed.host)) {
		return HTTP_BAD_REQUEST;
	}

	/* request line, origin-form */
	const char *const path = (parsed.path != NULL) ? parsed.path : "";
	bool ok = fwd_append(p, method) && fwd_append(p, " /") &&
		  fwd_append(p, path);
	if (parsed.query != NULL) {
		ok = ok && fwd_append(p, "?") && fwd_append(p, parsed.query);
	}
	/* RFC 9110 §6.2: an intermediary sends its own HTTP version in forwarded
	 * messages, not the client's; the received protocol still travels in the
	 * Via entry below. */
	ok = ok && fwd_append(p, " HTTP/1.1\r\n");
	/* RFC 9112 §3.2.2: regenerate Host from the request target */
	ok = ok && fwd_append(p, "Host: ") && fwd_append(p, parsed.host) &&
	     fwd_append(p, "\r\n");
	/* end-to-end headers, except those listed in Connection */
	struct buffer *restrict wbuf = (struct buffer *)&p->wbuf;
	ok = ok &&
	     http_append_headers(
		     wbuf, ctx->fwd_hdr, ctx->num_fwd_hdr, p->hdr.connection);
	/* RFC 9110 §7.6.3: append our Via entry after any client Via */
	ok = ok && fwd_append(p, "Via: ") && fwd_append(p, version + 5) &&
	     fwd_append(p, " neosocksd\r\n");
	ok = ok &&
	     http_append_framing(
		     wbuf, p->hdr.transfer.encoding == TENCODING_CHUNKED,
		     ctx->req_content_length_known, ctx->req_content_length);
	/* RFC 9110 §7.8: a bodiless request that asks to switch protocols
	 * (Connection lists "upgrade" and an Upgrade header is present) is
	 * forwarded with those hop-by-hop headers intact and then tunneled raw
	 * (see send_cb): the upstream's 101 Switching Protocols and every
	 * post-upgrade byte pass through untouched. A body alongside the upgrade
	 * is malformed for WebSocket and disables the upgrade, degrading to an
	 * ordinary framed request. */
	ctx->req_upgrade =
		ctx->req_upgrade_value != NULL &&
		http_connection_lists(p->hdr.connection, "upgrade") &&
		!ctx->req_content_length_known &&
		p->hdr.transfer.encoding != TENCODING_CHUNKED;
	if (ctx->req_upgrade) {
		ok = ok && fwd_append(p, "Connection: upgrade\r\nUpgrade: ") &&
		     fwd_append(p, ctx->req_upgrade_value) &&
		     fwd_append(p, "\r\n\r\n");
	} else {
		/* the client Connection/Keep-Alive headers were dropped above;
		 * overwrite the upstream connection disposition to close (no
		 * keep-alive) to keep the proxy stateless and bound the response
		 * by the upstream EOF */
		ok = ok && fwd_append(p, "Connection: close\r\n\r\n");
	}
	if (!ok) {
		return HTTP_ENTITY_TOO_LARGE;
	}
	/* The request body is not buffered here: the framing forwarder
	 * (http_ctx_start_stream) consumes the readahead directly from rbuf and
	 * dechunks/length-bounds the rest, so surplus bytes past the declared
	 * body can never be smuggled to the upstream. */
	return 0;
}

/* Build the dial request for @p addr_str into *out. Returns 0 on success,
 * HTTP_BAD_REQUEST for an unparsable client-supplied target, or
 * HTTP_INTERNAL_SERVER_ERROR on OOM. */
static uint_fast16_t make_dialreq(
	struct http_ctx *restrict ctx, const char *restrict addr_str,
	struct dialreq **restrict out)
{
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
	if (req == NULL) {
		LOGOOM();
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!dialaddr_parse(&req->addr, addr_str, strlen(addr_str))) {
		dialreq_free(req);
		return HTTP_BAD_REQUEST;
	}
	*out = req;
	return 0;
}

static void http_proxy_pass(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	const uint_fast16_t code = build_forward_req(ctx);
	if (code != 0) {
		send_errpage(loop, ctx, code);
		return;
	}

	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "http: %s `%s'", p->msg.req.method,
		p->msg.req.url);

#if WITH_RULESET
	const struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif
	const uint_fast16_t dial_code =
		make_dialreq(ctx, ctx->req_target, &ctx->dialreq);
	if (dial_code != 0) {
		send_errpage(loop, ctx, dial_code);
		return;
	}
	http_connect(loop, ctx);
}

static void
http_proxy_handle(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->conn.msg;
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		http_proxy_pass(loop, ctx);
		return;
	}

	const char *const addr_str = ctx->conn.msg.req.url;
	HTTP_CTX_LOG_F(VERBOSE, ctx, "http: CONNECT `%s'", addr_str);
#if WITH_RULESET
	const struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif

	const uint_fast16_t dial_code =
		make_dialreq(ctx, addr_str, &ctx->dialreq);
	if (dial_code != 0) {
		send_errpage(loop, ctx, dial_code);
		return;
	}
	http_connect(loop, ctx);
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;

	const int want = http_conn_recv(&ctx->conn);
	if (want < 0) {
		gc_unref(&ctx->gcbase);
		return;
	}
	if (want > 0) {
		return;
	}
	ctx->state = STATE_PROCESS;
	ev_io_stop(loop, watcher);

	switch (ctx->conn.state) {
	case STATE_PARSE_OK: {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
	} break;
	case STATE_PARSE_ERROR:
		send_errpage(loop, ctx, ctx->conn.http_status);
		return;
	default:
		FAILMSGF("unexpected http parser state: %d", ctx->conn.state);
	}

	http_proxy_handle(loop, ctx);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	if (ctx->state == STATE_STREAM) {
		/* the upstream never produced response headers; deliver a 504 if
		 * nothing has reached the client yet, matching the dialer-failure
		 * 502, rather than a bare FIN with no status */
		HTTP_CTX_LOG(DEBUG, ctx, "stream idle timeout");
		stream_fail(loop, ctx->stream, HTTP_GATEWAY_TIMEOUT);
		return;
	}
	if (ctx->state == STATE_CONNECT) {
		/* the dial deadline passed: cancel it and answer 504 rather than
		 * closing the client with no status */
		HTTP_CTX_LOG(WARNING, ctx, "connect timeout");
		dialer_cancel(&ctx->dialer, loop);
		ctx->s->stats.num_reject_timeout++;
		send_errpage(loop, ctx, HTTP_GATEWAY_TIMEOUT);
		return;
	}
	/* any other pre-stream handshake deadline: the connection never
	 * established, just close */
	ctx->s->stats.num_reject_timeout++;
	gc_unref(&ctx->gcbase);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct http_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		char errbuf[128];
		HTTP_CTX_LOG_F(
			ERROR, ctx, "dialer: %s",
			dialer_errorstr(errbuf, sizeof(errbuf), &ctx->dialer));
		ctx->s->stats.num_reject_upstream++;
		send_errpage(loop, ctx, HTTP_BAD_GATEWAY);
		return;
	}
	http_commit(loop, ctx, fd);
}

/* Handle end-to-end headers for proxy_pass mode; validates and records for build_forward_req(). */
static bool parse_header_proxy_pass(
	struct http_ctx *restrict ctx, struct http_conn *restrict p,
	const char *key, char *value)
{
	if (strcasecmp(key, "Host") == 0) {
		/* reject duplicate Host to avoid request smuggling */
		if (p->hdr.host != NULL) {
			return false;
		}
		p->hdr.host = value;
		/* not recorded: Host is regenerated from the request target */
		return true;
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		/* RFC 9112 §6.3: reject duplicate CL or CL+TE:chunked conflict */
		if (ctx->req_content_length_known ||
		    p->hdr.transfer.encoding == TENCODING_CHUNKED) {
			return false;
		}
		if (!http_parse_content_length(
			    value, &ctx->req_content_length)) {
			return false;
		}
		ctx->req_content_length_known = true;
		/* not recorded: the canonical value is emitted at rebuild */
		return true;
	}
	if (strcasecmp(key, "Expect") == 0 &&
	    strcasecmp(value, "100-continue") == 0) {
		/* Expect: 100-continue means the client has a request body */
		p->expect_continue = true;
	}
	/* record all other end-to-end headers for forwarding */
	if (ctx->num_fwd_hdr >= ARRAY_SIZE(ctx->fwd_hdr)) {
		p->http_status = HTTP_ENTITY_TOO_LARGE;
		return false;
	}
	ctx->fwd_hdr[ctx->num_fwd_hdr].key = key;
	ctx->fwd_hdr[ctx->num_fwd_hdr].value = value;
	ctx->num_fwd_hdr++;
	return true;
}

static bool parse_header(void *data, const char *key, char *value)
{
	struct http_ctx *restrict ctx = (struct http_ctx *)data;
	struct http_conn *restrict p = &ctx->conn;
	const bool is_connect = (strcmp(p->msg.req.method, "CONNECT") == 0);

	/* RFC 7230 §3.2.6 / RFC 9112 §2.2: validate field name (tchar only)
	 * and field value (no CTL except HTAB, no DEL). */
	if (!http_header_field_valid(key, value)) {
		return false;
	}

	/* hop-by-hop headers: handle but never forward */
	if (strcasecmp(key, "Connection") == 0) {
		return parsehdr_connection(p, value);
	}
	if (strcasecmp(key, "Keep-Alive") == 0) {
		return true;
	}
	if (strcasecmp(key, "Proxy-Authorization") == 0) {
		char *const sep = strchr(value, ' ');
		if (sep == NULL) {
			return false;
		}
		*sep = '\0';
		p->hdr.proxy_authorization.type = value;
		p->hdr.proxy_authorization.credentials = sep + 1;
		return true;
	}
	if (strcasecmp(key, "Proxy-Connection") == 0) {
		/* fall back to Proxy-Connection for legacy HTTP/1.0 clients */
		if (p->hdr.connection == NULL) {
			parsehdr_connection(p, value);
		}
		return true;
	}
	if (strcasecmp(key, "TE") == 0) {
		/* RFC 9110 §10.1.4: TE only advertises which transfer-codings the
		 * client accepts, so accept any value and do not vary framing on
		 * it (chunked is always acceptable per RFC 9112 §7.4) */
		return true;
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		if (!parsehdr_transfer_encoding(p, value)) {
			return false;
		}
		/* RFC 9112 §6.3: CL+TE coexistence must be rejected */
		if (!is_connect &&
		    p->hdr.transfer.encoding == TENCODING_CHUNKED &&
		    ctx->req_content_length_known) {
			return false;
		}
		return true;
	}
	if (strcasecmp(key, "Upgrade") == 0) {
		/* hop-by-hop, never forwarded verbatim; retained so a bodiless
		 * upgrade request (e.g. WebSocket) can be re-emitted and tunneled
		 * by build_forward_req */
		ctx->req_upgrade_value = value;
		return true;
	}
	if (strcasecmp(key, "Trailer") == 0) {
		return true;
	}

	if (is_connect) {
		/* CONNECT sets up a tunnel; all remaining request headers are
		 * ignored (proxy auth is handled via Proxy-Authorization) */
		return true;
	}
	return parse_header_proxy_pass(ctx, p, key, value);
}

static struct http_ctx *http_ctx_new(struct server *restrict s, const int fd)
{
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;

	ev_timer_init(&ctx->w_timeout, timeout_cb, s->conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_recv, recv_cb, fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, send_cb, fd, EV_WRITE);
	ctx->w_send.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	ev_init(&ctx->ruleset_callback.w_finish, ruleset_cb);
	ctx->ruleset_callback.w_finish.data = ctx;
	ctx->ruleset_callback.forward = http_forward_commit;
	ctx->ruleset_state = NULL;
#endif
	ctx->dialreq = NULL;
	ctx->stream = NULL;
	ctx->req_content_length = 0;
	ctx->req_content_length_known = false;
	ctx->req_upgrade = false;
	ctx->req_upgrade_value = NULL;
	ctx->num_fwd_hdr = 0;
	ctx->req_target[0] = '\0';
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(
		&ctx->dialer, &cb, &s->stats.byt_dial_send,
		&s->stats.byt_dial_recv);
	const struct http_parsehdr_cb on_header = {
		.func = parse_header,
		.ctx = ctx,
	};
	http_conn_init(
		&ctx->conn, fd, STATE_PARSE_REQUEST, on_header,
		&s->stats.byt_client_recv, &s->stats.byt_client_send);

	gc_register(&ctx->gcbase, http_ctx_finalize);
	return ctx;
}

static void http_ctx_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_start(loop, &ctx->w_timeout);

	ctx->state = STATE_REQUEST;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen++;
}

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct http_ctx *restrict ctx = http_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		socket_close(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	http_ctx_start(loop, ctx);
}
