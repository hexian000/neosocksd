/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for http_client.c; mocked: dialer. */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "resolver.h"

#include "utils/buffer.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - dialer/dialreq stubs and shared fixtures.
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 0.2,
};

/* the plain client every case builds: no byte counters, no resolver */
static const struct http_client_opts test_opts = {
	.conf = &test_conf,
};

static struct {
	int dialer_result_fd;
	enum dialer_error dialer_err;
	int dialer_syserr;
	/* when true, dialer_do records the call but does not complete, leaving
	 * the client in STATE_CLIENT_CONNECT so cancel/timeout-during-connect can
	 * be observed */
	bool dialer_pending;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialreq_free_calls;
} S = {
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_pending = false,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.dialreq_free_calls = 0,
};

static void stub_reset(void)
{
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.dialer_pending = false;
	S.dialer_do_calls = 0;
	S.dialer_cancel_calls = 0;
	S.dialreq_free_calls = 0;
}

/* ---- dialer stubs ---- */

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub error";
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *byt_sent, uint_least64_t *byt_recv)
{
	(void)byt_sent;
	(void)byt_recv;
	d->finish_cb = *callback;
	d->err = DIALER_OK;
	d->syserr = 0;
}

void dialer_do(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct dialreq *req, const struct config *conf,
	struct resolver *resolver, struct server *server)
{
	(void)req;
	(void)conf;
	(void)resolver;
	(void)server;
	S.dialer_do_calls++;
	if (S.dialer_pending) {
		/* stay in-flight: the client remains in STATE_CLIENT_CONNECT */
		return;
	}
	d->err = S.dialer_err;
	d->syserr = S.dialer_syserr;
	/* a request dials once: fail any further dial rather than hand back
	 * an fd the client has already closed, so a stray redial surfaces as
	 * a "connection failed" result */
	const int fd = (S.dialer_do_calls == 1) ? S.dialer_result_fd : -1;
	d->finish_cb.func(loop, d->finish_cb.data, fd);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	(void)d;
	(void)loop;
	S.dialer_cancel_calls++;
}

void dialreq_free(struct dialreq *req)
{
	S.dialreq_free_calls++;
	free(req);
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/* ---- callback capture ---- */

struct cb_result {
	bool called;
	/* copy of the error message: errmsg may point into send_cb's stack
	 * buffer, whose lifetime ends before the test reads it, so it must be
	 * copied here (like the body below) rather than stored as a pointer */
	bool has_errmsg;
	char errmsg[64];
	size_t errlen;
	bool has_conn;
	char rsp_code[8];
	/* copy of the parsed response body, captured while conn is still valid
	 * (http_client_cleanup frees conn->cbuf right after the callback) */
	bool has_body;
	size_t body_len;
	char body[64];
};

static void capture_cb(
	struct ev_loop *loop, void *data, const char *errmsg,
	const size_t errlen, struct http_conn *conn)
{
	struct cb_result *restrict r = data;
	(void)loop;
	r->called = true;
	r->has_errmsg = (errmsg != NULL);
	r->errlen = errlen;
	if (errmsg != NULL) {
		const size_t n =
			errlen < sizeof(r->errmsg) ? errlen : sizeof(r->errmsg);
		memcpy(r->errmsg, errmsg, n);
	}
	r->has_conn = (conn != NULL);
	if (conn != NULL && conn->msg.rsp.code != NULL) {
		(void)snprintf(
			r->rsp_code, sizeof(r->rsp_code), "%s",
			conn->msg.rsp.code);
	}
	if (conn != NULL && conn->cbuf != NULL) {
		r->has_body = true;
		const size_t n = VBUF_LEN(conn->cbuf);
		r->body_len = n;
		if (n <= sizeof(r->body)) {
			memcpy(r->body, VBUF_DATA(conn->cbuf), n);
		}
	}
}

/* whether the callback reported exactly the error message msg */
static bool
result_errmsg_is(const struct cb_result *restrict r, const char *msg)
{
	const size_t n = strlen(msg);
	return r->has_errmsg && r->errlen == n &&
	       memcmp(r->errmsg, msg, n) == 0;
}

/* A user on_header callback: records that headers reach the user, and
 * dispatches Content-Length so a response body is parsed into conn->cbuf. */
struct hdr_capture {
	struct http_client_ctx *client;
	int count;
	bool saw_server;
	bool saw_custom;
};

static bool record_header_cb(void *data, const char *key, char *value)
{
	struct hdr_capture *restrict h = data;
	h->count++;
	if (strcmp(key, "Server") == 0 && strcmp(value, "test-server") == 0) {
		h->saw_server = true;
	}
	if (strcmp(key, "X-Custom") == 0 && strcmp(value, "hello") == 0) {
		h->saw_custom = true;
	}
	if (strcmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(&h->client->conn, value);
	}
	return true;
}

/* ---- tests ---- */

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - request lifecycle and dialer-outcome handling.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(http_client_init_state)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_INIT);
	T_EXPECT(ctx.cb.func == capture_cb);
	T_EXPECT(ctx.cb.data == &result);
	T_EXPECT(ctx.conf == &test_conf);
	T_EXPECT(!result.called);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(http_client_cancel_noop)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);
	http_client_cancel(&ctx, loop);
	/* cancel should not invoke the user callback */
	T_EXPECT(!result.called);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_INIT);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(http_client_dialer_fail_calls_cb)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();
	S.dialer_result_fd = -1;

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	/* dialer_do stub immediately fires finish_cb with fd=-1 */
	http_client_do(&ctx, loop, req);

	T_EXPECT(result.called);
	T_EXPECT(result.has_errmsg);
	T_EXPECT(result.errlen > 0);
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

/*
 * When the peer accepts but never responds, the request timer
 * (http_client_timeout_cb) must finish the callback with a "timeout" error.
 * The timer event is fed directly rather than waited on, per the test
 * conventions.
 */
T_DECLARE_CASE(http_client_timeout_finishes_with_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);
	static const char header[] = "GET /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	/* the request goes out but the peer never responds: no callback yet */
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(!result.called);

	/* fire the request timeout deterministically instead of waiting out
	 * test_conf.timeout */
	ev_feed_event(loop, &ctx.w_timeout, EV_TIMER);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT(result.called);
	T_CHECK(result.has_errmsg);
	T_EXPECT_EQ(result.errlen, sizeof("timeout") - 1);
	T_EXPECT_MEMEQ(result.errmsg, "timeout", sizeof("timeout") - 1);
	/* an error finish delivers no connection */
	T_EXPECT(!result.has_conn);

	/* the connection fd and dialreq are owned and released by http_client */
	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

/*
 * Regression: a peer that resets the connection mid-request (after a partial
 * write, as a server does when it answers early and closes with the body
 * unread) must finish the request with the write error, on the one connection
 * it was dialed -- not redial and re-upload the request from the start. The
 * body is large enough that no realistic socket buffer accepts it in one
 * send(), guaranteeing a genuine partial write before the peer is closed out
 * from under it.
 */
T_DECLARE_CASE(http_client_reset_mid_request_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	static unsigned char body[2 * 1024 * 1024];
	for (size_t i = 0; i < sizeof(body); i++) {
		body[i] = (unsigned char)(i & 0xff);
	}
	ctx.conn.cbuf = VBUF_NEW(sizeof(body));
	T_CHECK(ctx.conn.cbuf != NULL);
	VBUF_APPEND(ctx.conn.cbuf, body, sizeof(body));

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	/* This case exercises the write error, not the request deadline, but
	 * http_client_do just armed it: were it left running, a stall longer
	 * than test_conf.timeout would finish the request with a "timeout" error
	 * that the assertions below must not mistake for the write error. Drop
	 * it; http_client_timeout_finishes_with_error covers the deadline. Every
	 * loop below is bounded by its own iteration cap instead. */
	ev_timer_stop(loop, &ctx.w_timeout);

	/* Drive sends until the header is fully out and the body is genuinely
	 * (not artificially) partial. EVRUN_NOWAIT, never EVRUN_ONCE: with the
	 * deadline stopped a blocking iteration would have nothing left to wake
	 * it if the socket were not ready, and the cap is the failing bound. */
	for (int i = 0;
	     i < 50 && !(ctx.conn.wpos == sizeof(header) - 1 &&
			 ctx.conn.cpos > 0 && ctx.conn.cpos < sizeof(body));
	     i++) {
		ev_run(loop, EVRUN_NOWAIT);
	}
	T_EXPECT_EQ(ctx.conn.wpos, sizeof(header) - 1);
	T_CHECK(ctx.conn.cpos > 0);
	T_CHECK(ctx.conn.cpos < sizeof(body));

	/* the peer disappears mid-transfer */
	T_CHECK(close(sv[1]) == 0);

	/* the next write hits the dead peer and finishes the request */
	for (int i = 0; i < 20 && !result.called; i++) {
		ev_run(loop, EVRUN_NOWAIT);
	}
	T_EXPECT(result.called);
	T_EXPECT(result_errmsg_is(&result, strerror(EPIPE)));
	T_EXPECT(!result.has_conn);
	T_EXPECT_EQ(S.dialer_do_calls, 1);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_INIT);

	ev_loop_destroy(loop);
}

/* Drive a request through to a complete, parsed response and observe recv_cb's
 * success path (previously untested at this module's level). */
T_DECLARE_CASE(http_client_full_request_response)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	/* drive the request out, then reply with a complete response */
	for (int i = 0; i < 20 && ctx.state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	static const char resp[] = "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n";
	T_CHECK(write(sv[1], resp, sizeof(resp) - 1) ==
		(ssize_t)(sizeof(resp) - 1));

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	T_EXPECT(!result.has_errmsg);
	T_EXPECT(result.has_conn);
	T_EXPECT_STREQ(result.rsp_code, "200");

	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

T_DECLARE_SUBCASE(interim_responses, const bool split)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	S.dialer_result_fd = sv[0];
	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	struct hdr_capture hdrs = { .client = &ctx };
	const struct http_parsehdr_cb on_header = {
		.func = record_header_cb,
		.ctx = &hdrs,
	};
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	uint_least64_t received = 0, sent = 0;
	const struct http_client_opts opts = {
		.conf = &test_conf,
		.byt_recv = &received,
		.byt_sent = &sent,
	};
	http_client_init(&ctx, loop, on_header, &cb, &opts);
	static const char request[] = "GET /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, request, sizeof(request) - 1);
	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);
	for (int i = 0; i < 20 && ctx.state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_CHECK(ctx.state == STATE_CLIENT_RESPONSE);
	static const char interim[] =
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 103 Early Hints\r\n"
		"Server: interim\r\nContent-Length: 999\r\n\r\n";
	static const char final[] = "HTTP/1.1 200 OK\r\nServer: test-server\r\n"
				    "Content-Length: 5\r\n\r\nhello";
	char response[sizeof(interim) + sizeof(final)];
	memcpy(response, interim, sizeof(interim) - 1);
	memcpy(response + sizeof(interim) - 1, final, sizeof(final) - 1);
	if (split) {
		T_CHECK(write(sv[1], interim, sizeof(interim) - 1) ==
			(ssize_t)(sizeof(interim) - 1));
		for (int i = 0;
		     i < 20 && received < sizeof(interim) - 1 && !result.called;
		     i++) {
			ev_run(loop, EVRUN_ONCE);
		}
		T_CHECK(received == sizeof(interim) - 1);
		T_CHECK(!result.called);
		T_EXPECT_EQ(hdrs.count, 0);
		/* Split the final status line too: compaction must preserve
		 * a partial next message as well as a complete one. */
		T_CHECK(write(sv[1], final, 8) == 8);
		for (int i = 0; i < 20 && received < sizeof(interim) - 1 + 8 &&
				!result.called;
		     i++) {
			ev_run(loop, EVRUN_ONCE);
		}
		T_CHECK(!result.called);
		T_CHECK(write(sv[1], final + 8, sizeof(final) - 1 - 8) ==
			(ssize_t)(sizeof(final) - 1 - 8));
	} else {
		const size_t total = sizeof(interim) + sizeof(final) - 2;
		T_CHECK(write(sv[1], response, total) == (ssize_t)total);
	}
	for (int i = 0; i < 20 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_CHECK(result.called);
	T_EXPECT(!result.has_errmsg);
	T_EXPECT_STREQ(result.rsp_code, "200");
	T_EXPECT_EQ(result.body_len, 5);
	T_EXPECT_MEMEQ(result.body, "hello", 5);
	T_EXPECT_EQ(hdrs.count, 2);
	T_EXPECT(hdrs.saw_server);
	T_EXPECT_EQ(received, sizeof(interim) + sizeof(final) - 2);
	T_EXPECT_EQ(sent, sizeof(request) - 1);
	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(http_client_coalesced_interim_responses)
{
	T_CALL_SUBCASE(interim_responses, false);
}

T_DECLARE_CASE(http_client_split_interim_responses)
{
	T_CALL_SUBCASE(interim_responses, true);
}

/* A user on_header callback must receive each final response header. */
T_DECLARE_CASE(http_client_forwards_response_headers)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	struct hdr_capture hdrs = { .client = &ctx };
	const struct http_parsehdr_cb on_header = {
		.func = record_header_cb,
		.ctx = &hdrs,
	};
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, on_header, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	for (int i = 0; i < 20 && ctx.state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "Server: test-server\r\n"
				   "X-Custom: hello\r\n\r\n";
	T_CHECK(write(sv[1], resp, sizeof(resp) - 1) ==
		(ssize_t)(sizeof(resp) - 1));

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	T_EXPECT(result.has_conn);
	T_EXPECT(hdrs.count >= 2);
	T_EXPECT(hdrs.saw_server);
	T_EXPECT(hdrs.saw_custom);

	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

/* A response body must be parsed into conn->cbuf and be readable from the
 * completion callback -- the other primary reason to use this module, and
 * previously untested (every prior case used a bodiless 200). */
T_DECLARE_CASE(http_client_delivers_response_body)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	struct hdr_capture hdrs = { .client = &ctx };
	const struct http_parsehdr_cb on_header = {
		.func = record_header_cb,
		.ctx = &hdrs,
	};
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, on_header, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	for (int i = 0; i < 20 && ctx.state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "Content-Length: 5\r\n\r\n"
				   "hello";
	T_CHECK(write(sv[1], resp, sizeof(resp) - 1) ==
		(ssize_t)(sizeof(resp) - 1));

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	T_EXPECT(!result.has_errmsg);
	T_EXPECT(result.has_conn);
	T_EXPECT_STREQ(result.rsp_code, "200");
	T_EXPECT(result.has_body);
	T_EXPECT_EQ(result.body_len, 5);
	T_EXPECT_MEMEQ(result.body, "hello", 5);

	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

/* recv_cb's hard receive-error path: the peer closes before sending any
 * response, so recv() reports early EOF and the callback gets an error. */
T_DECLARE_CASE(http_client_recv_eof_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	for (int i = 0; i < 20 && ctx.state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	/* peer closes without responding */
	T_CHECK(close(sv[1]) == 0);

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	/* the exact message tells the EOF path from the request deadline, which
	 * would also finish a stalled request with an error */
	T_EXPECT(result_errmsg_is(&result, "error receiving response"));
	T_EXPECT(!result.has_conn);

	ev_loop_destroy(loop);
}

/*
 * send_cb's write-error path builds the error message from strerror() in a
 * stack buffer. Dial to a socket whose peer is already closed: the first write
 * fails with EPIPE and must finish the request with that message, without a
 * second dial.
 */
T_DECLARE_CASE(http_client_write_error_reports_strerror)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(close(sv[1]) == 0);
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	/* the exact message tells the write error from the request deadline */
	T_EXPECT(result_errmsg_is(&result, strerror(EPIPE)));
	T_EXPECT(!result.has_conn);
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

/* Drive one request to a peer that answers with resp, then run the loop until
 * the completion callback fires; the request deadline stays armed as the
 * failsafe, and the caller pins the message to tell a result from it. */
static void run_request_with_response(
	struct ev_loop *loop, const struct http_parsehdr_cb on_header,
	struct http_client_ctx *restrict ctx, struct cb_result *restrict result,
	const char *resp)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];

	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = result,
	};
	http_client_init(ctx, loop, on_header, &cb, &test_opts);

	static const char header[] = "GET /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx->conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(ctx, loop, req);

	for (int i = 0; i < 20 && ctx->state == STATE_CLIENT_REQUEST; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	const size_t n = strlen(resp);
	T_CHECK(write(sv[1], resp, n) == (ssize_t)n);

	for (int i = 0; i < 50 && !result->called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	(void)close(sv[1]);
}

/* recv_cb's parse-error branch: a response header the parser rejects -- here
 * a Content-Length over HTTP_MAX_CONTENT -- must finish with a parse error and
 * no connection. */
T_DECLARE_CASE(http_client_oversized_content_reports_parse_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	struct hdr_capture hdrs = { .client = &ctx };
	const struct http_parsehdr_cb on_header = {
		.func = record_header_cb,
		.ctx = &hdrs,
	};
	char resp[128];
	T_CHECK(snprintf(
			resp, sizeof(resp),
			"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n",
			HTTP_MAX_CONTENT + 1) > 0);
	run_request_with_response(loop, on_header, &ctx, &result, resp);

	T_EXPECT(result.called);
	T_EXPECT(result_errmsg_is(&result, "error parsing response"));
	T_EXPECT(!result.has_conn);

	ev_loop_destroy(loop);
}

/* recv_cb's parse-error branch reached through the user header callback: a
 * header it rejects must finish with a parse error and no connection. */
T_DECLARE_CASE(http_client_rejected_header_reports_parse_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	struct hdr_capture hdrs = { .client = &ctx };
	const struct http_parsehdr_cb on_header = {
		.func = record_header_cb,
		.ctx = &hdrs,
	};
	/* parsehdr_content_length rejects a non-numeric length */
	run_request_with_response(
		loop, on_header, &ctx, &result,
		"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n");

	T_EXPECT(result.called);
	T_EXPECT(result_errmsg_is(&result, "error parsing response"));
	T_EXPECT(!result.has_conn);

	ev_loop_destroy(loop);
}

/* A status line that is not HTTP/1.x is a receive error (http_conn_recv < 0),
 * not a parse error: the response parser gives up on the message outright. */
T_DECLARE_CASE(http_client_non_http1_status_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	run_request_with_response(
		loop, no_hdr, &ctx, &result, "SPDY/3 200 OK\r\n\r\n");

	T_EXPECT(result.called);
	T_EXPECT(result_errmsg_is(&result, "error receiving response"));
	T_EXPECT(!result.has_conn);

	ev_loop_destroy(loop);
}

/* Cancelling while the dial is still in flight (STATE_CLIENT_CONNECT) must
 * cancel the dialer and fire no callback -- http_client_stop's dialer_cancel
 * branch, unreachable with a synchronously-completing dialer stub. */
T_DECLARE_CASE(http_client_cancel_during_connect_cancels_dialer)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();
	S.dialer_pending = true;

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);
	/* the dial is in-flight: the client is parked in CONNECT */
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_CONNECT);
	T_EXPECT(!result.called);

	http_client_cancel(&ctx, loop);
	T_EXPECT_EQ(S.dialer_cancel_calls, 1);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_INIT);

	ev_loop_destroy(loop);
}

/* The request timeout firing while the dial is still in flight must cancel the
 * dialer and finish with a "timeout" error. */
T_DECLARE_CASE(http_client_timeout_during_connect_cancels_dialer)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();
	S.dialer_pending = true;

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_CONNECT);

	/* fire the request timeout deterministically */
	ev_feed_event(loop, &ctx.w_timeout, EV_TIMER);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT(result.called);
	T_EXPECT(result.has_errmsg);
	T_EXPECT_MEMEQ(result.errmsg, "timeout", sizeof("timeout") - 1);
	T_EXPECT(!result.has_conn);
	T_EXPECT_EQ(S.dialer_cancel_calls, 1);

	ev_loop_destroy(loop);
}

/* Cancelling while the request write watcher is active (STATE_CLIENT_REQUEST)
 * must stop the io watcher, close the fd and fire no callback -- the
 * STATE_CLIENT_REQUEST/RESPONSE branch of http_client_stop. */
T_DECLARE_CASE(http_client_cancel_during_request_stops_io)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	S.dialer_result_fd = sv[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(&ctx, loop, no_hdr, &cb, &test_opts);

	static const char header[] = "GET /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	/* synchronous dial: the client transitions to REQUEST with its write
	 * watcher active (the send happens on the next loop iteration) */
	http_client_do(&ctx, loop, req);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_REQUEST);
	T_EXPECT(ev_is_active(&ctx.w_socket));

	http_client_cancel(&ctx, loop);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(ctx.state, STATE_CLIENT_INIT);
	T_EXPECT(!ev_is_active(&ctx.w_socket));

	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(http_client_init_state),
	T_CASE(http_client_cancel_noop),
	T_CASE(http_client_dialer_fail_calls_cb),
	T_CASE(http_client_timeout_finishes_with_error),
	T_CASE(http_client_reset_mid_request_reports_error),
	T_CASE(http_client_full_request_response),
	T_CASE(http_client_coalesced_interim_responses),
	T_CASE(http_client_split_interim_responses),
	T_CASE(http_client_forwards_response_headers),
	T_CASE(http_client_delivers_response_body),
	T_CASE(http_client_recv_eof_reports_error),
	T_CASE(http_client_write_error_reports_strerror),
	T_CASE(http_client_oversized_content_reports_parse_error),
	T_CASE(http_client_rejected_header_reports_parse_error),
	T_CASE(http_client_non_http1_status_reports_error),
	T_CASE(http_client_cancel_during_connect_cancels_dialer),
	T_CASE(http_client_timeout_during_connect_cancels_dialer),
	T_CASE(http_client_cancel_during_request_stops_io),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Ignore SIGPIPE: writing to a closed peer in the write-error cases
	 * returns EPIPE instead of killing the process. */
	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	(void)sigaction(SIGPIPE, &ignore, NULL);

	return testing_main(argc, argv, suite);
}
