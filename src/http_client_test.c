/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for http_client.c; mocked: dialer. */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/testing.h"

#include <ev.h>

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

static struct {
	int dialer_result_fd;
	/* used on the 2nd dialer_do call instead of dialer_result_fd, when
	 * >= 0 -- lets a test simulate a stale-connection retry redialing
	 * to a second, distinct fd */
	int dialer_result_fd2;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialreq_free_calls;
} S = {
	.dialer_result_fd = -1,
	.dialer_result_fd2 = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.dialreq_free_calls = 0,
};

static void stub_reset(void)
{
	S.dialer_result_fd = -1;
	S.dialer_result_fd2 = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
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
	d->err = S.dialer_err;
	d->syserr = S.dialer_syserr;
	const int fd = (S.dialer_do_calls == 2 && S.dialer_result_fd2 >= 0) ?
			       S.dialer_result_fd2 :
			       S.dialer_result_fd;
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
	const char *errmsg;
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
	r->errmsg = errmsg;
	r->errlen = errlen;
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

	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);
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

	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);
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

	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	/* dialer_do stub immediately fires finish_cb with fd=-1 */
	http_client_do(&ctx, loop, req);

	T_EXPECT(result.called);
	T_EXPECT(result.errmsg != NULL);
	T_EXPECT(result.errlen > 0);
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

/*
 * Regression: a stale-connection retry (after a successful partial write
 * followed by a hard write error) must resend the whole request on the
 * fresh connection, not resume from the dead connection's offset. The
 * body is large enough that no realistic socket buffer accepts it in one
 * send(), guaranteeing a genuine partial write before sv1's peer is
 * closed out from under it.
 */
T_DECLARE_CASE(http_client_stale_retry_resends_from_start)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv1[2] = { -1, -1 };
	int sv2[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
	T_CHECK(fd_set_nonblock(sv1[0]));
	T_CHECK(fd_set_nonblock(sv2[0]));

	S.dialer_result_fd = sv1[0];
	S.dialer_result_fd2 = sv2[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};

	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

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

	/* drive sends until the header is fully out and the body is
	 * genuinely (not artificially) partial */
	for (int i = 0;
	     i < 50 && !(ctx.conn.wpos == sizeof(header) - 1 &&
			 ctx.conn.cpos > 0 && ctx.conn.cpos < sizeof(body));
	     i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT_EQ(ctx.conn.wpos, sizeof(header) - 1);
	T_CHECK(ctx.conn.cpos > 0);
	T_CHECK(ctx.conn.cpos < sizeof(body));

	/* the peer disappears mid-transfer */
	T_CHECK(close(sv1[1]) == 0);

	/* the next write hits the dead peer and must retry from scratch */
	for (int i = 0; i < 20 && S.dialer_do_calls < 2; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT_EQ(S.dialer_do_calls, 2);
	T_EXPECT_EQ(ctx.conn.wpos, 0);
	T_EXPECT_EQ(ctx.conn.cpos, 0);

	/* let it resend on the fresh connection */
	for (int i = 0; i < 20; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	unsigned char received[sizeof(header) - 1 + 256];
	const ssize_t n = read(sv2[1], received, sizeof(received));
	T_CHECK(n > (ssize_t)(sizeof(header) - 1));
	T_EXPECT_MEMEQ(received, header, sizeof(header) - 1);
	T_EXPECT_MEMEQ(
		received + sizeof(header) - 1, body,
		(size_t)n - (sizeof(header) - 1));

	http_client_cancel(&ctx, loop);
	(void)close(sv2[1]);
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
	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

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
	T_EXPECT(result.errmsg == NULL);
	T_EXPECT(result.has_conn);
	T_EXPECT_STREQ(result.rsp_code, "200");

	(void)close(sv[1]);
	ev_loop_destroy(loop);
}

/* A user on_header callback must receive each response header
 * (http_client_on_header forwards to it); previously every case passed an
 * empty header callback so this forwarding was unverified. */
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
	http_client_init(
		&ctx, loop, on_header, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

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
	http_client_init(
		&ctx, loop, on_header, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

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
	T_EXPECT(result.errmsg == NULL);
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
	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

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
	T_EXPECT(result.errmsg != NULL);
	T_EXPECT(result.errlen > 0);
	T_EXPECT(!result.has_conn);

	ev_loop_destroy(loop);
}

/*
 * send_cb's generic write-error path builds the error message from strerror()
 * in a stack buffer. Force it by dialing to two sockets whose peers are both
 * closed: the first write fails with EPIPE and retries, the retry redials to a
 * second (still valid but dead-peer) fd and fails again with the retry flag
 * set, so the generic path runs and must deliver a non-empty message.
 */
T_DECLARE_CASE(http_client_write_error_reports_strerror)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	stub_reset();

	int sv1[2] = { -1, -1 };
	int sv2[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
	T_CHECK(fd_set_nonblock(sv1[0]));
	T_CHECK(fd_set_nonblock(sv2[0]));
	T_CHECK(close(sv1[1]) == 0);
	T_CHECK(close(sv2[1]) == 0);
	S.dialer_result_fd = sv1[0];
	S.dialer_result_fd2 = sv2[0];

	struct http_client_ctx ctx = { 0 };
	struct cb_result result = { 0 };
	const struct http_parsehdr_cb no_hdr = { 0 };
	const struct http_client_cb cb = {
		.func = capture_cb,
		.data = &result,
	};
	http_client_init(
		&ctx, loop, no_hdr, &cb, &test_conf, NULL, NULL, NULL, NULL,
		NULL);

	static const char header[] = "POST /x HTTP/1.1\r\n\r\n";
	BUF_APPEND(ctx.conn.wbuf, header, sizeof(header) - 1);

	struct dialreq *req = calloc(1, sizeof(struct dialreq));
	T_CHECK(req != NULL);
	http_client_do(&ctx, loop, req);

	for (int i = 0; i < 50 && !result.called; i++) {
		ev_run(loop, EVRUN_ONCE);
	}
	T_EXPECT(result.called);
	T_EXPECT(result.errmsg != NULL);
	T_EXPECT(result.errlen > 0);
	T_EXPECT(!result.has_conn);
	T_EXPECT_EQ(S.dialer_do_calls, 2);

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
	T_CASE(http_client_stale_retry_resends_from_start),
	T_CASE(http_client_full_request_response),
	T_CASE(http_client_forwards_response_headers),
	T_CASE(http_client_delivers_response_body),
	T_CASE(http_client_recv_eof_reports_error),
	T_CASE(http_client_write_error_reports_strerror),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Ignore SIGPIPE: writing to the closed peer during the retry test
	 * returns EPIPE instead of killing the process. */
	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	(void)sigaction(SIGPIPE, &ignore, NULL);

	return testing_main(argc, argv, suite);
}
