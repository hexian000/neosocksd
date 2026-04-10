/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "util.h"

#include "io/stream.h"
#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WITH_RULESET

struct conn_cache conn_cache = { 0 };

static struct config test_conf = {
	.timeout = 0.2,
	.conn_cache = true,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.064;
static const ev_tstamp TEST_WAIT_RESPONSE_SEC = 0.256;
static const ev_tstamp TEST_WAIT_LONG_SEC = 0.512;

struct cb_result {
	bool called;
	char errmsg[256];
	size_t errlen;
	bool has_stream;
	unsigned char stream_buf[512];
	size_t stream_len;
};

struct stub_state {
	bool dialer_defer;
	int dialer_result_fd;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialreq_free_calls;
	int_least32_t conn_cache_get_calls;
	int_least32_t conn_cache_put_calls;
	int conn_cache_get_fd;
	int conn_cache_put_fd;
	const struct dialreq *conn_cache_put_req;
	bool close_fd_on_conn_put;
	struct ev_loop *pending_loop;
	struct dialer *pending_dialer;
};

static struct stub_state S = {
	.dialer_defer = false,
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.dialreq_free_calls = 0,
	.conn_cache_get_calls = 0,
	.conn_cache_put_calls = 0,
	.conn_cache_get_fd = -1,
	.conn_cache_put_fd = -1,
	.conn_cache_put_req = NULL,
	.close_fd_on_conn_put = true,
	.pending_loop = NULL,
	.pending_dialer = NULL,
};

static void reset_stub_state(void)
{
	S.dialer_defer = false;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.dialer_do_calls = 0;
	S.dialer_cancel_calls = 0;
	S.dialreq_free_calls = 0;
	S.conn_cache_get_calls = 0;
	S.conn_cache_put_calls = 0;
	S.conn_cache_get_fd = -1;
	S.conn_cache_put_fd = -1;
	S.conn_cache_put_req = NULL;
	S.close_fd_on_conn_put = true;
	S.pending_loop = NULL;
	S.pending_dialer = NULL;
	test_conf.timeout = 0.2;
	test_conf.conn_cache = true;
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool write_all(const int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		const ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (n == 0) {
			return false;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return true;
}

static ssize_t recv_nowait(const int fd, void *buf, const size_t len)
{
	for (;;) {
		const ssize_t n = recv(fd, buf, len, MSG_DONTWAIT);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return n;
	}
}

static void
read_stream_content(struct stream *stream, unsigned char *buf, size_t *len)
{
	size_t total = 0;
	while (total < *len) {
		size_t n = *len - total;
		if (stream_read(stream, buf + total, &n) != 0) {
			break;
		}
		if (n == 0) {
			break;
		}
		total += n;
	}
	*len = total;
}

static void capture_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const char *errmsg, size_t errlen, struct stream *stream)
{
	struct cb_result *const out = data;
	(void)ctx;
	(void)loop;
	out->called = true;
	out->errlen = errlen;
	if (errmsg != NULL) {
		const size_t copy_len = errlen < sizeof(out->errmsg) - 1 ?
						errlen :
						sizeof(out->errmsg) - 1;
		(void)memcpy(out->errmsg, errmsg, copy_len);
		out->errmsg[copy_len] = '\0';
	} else {
		out->errmsg[0] = '\0';
	}
	if (stream != NULL) {
		size_t n = sizeof(out->stream_buf);
		read_stream_content(stream, out->stream_buf, &n);
		out->has_stream = true;
		out->stream_len = n;
	} else {
		out->has_stream = false;
		out->stream_len = 0;
	}
}

struct test_watchdog {
	bool fired;
};

static void
test_watchdog_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	struct test_watchdog *const watchdog = w->data;
	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static bool cb_called_predicate(void *data)
{
	const struct cb_result *const r = data;
	return r->called;
}

struct fd_closed_ctx {
	int fd;
};

static bool fd_closed_predicate(void *data)
{
	struct fd_closed_ctx *const ctx = data;
	unsigned char ch;
	const ssize_t n = recv_nowait(ctx->fd, &ch, sizeof(ch));

	if (n == 0) {
		return true;
	}
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
		return false;
	}
	return false;
}

static bool read_request_headers(
	struct ev_loop *loop, const int fd, char *buf, const size_t cap,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	size_t off = 0;

	if (cap == 0) {
		return false;
	}
	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		if (off + 1 >= cap) {
			break;
		}
		const ssize_t n = recv_nowait(fd, buf + off, cap - off - 1);
		if (n > 0) {
			off += (size_t)n;
			buf[off] = '\0';
			if (strstr(buf, "\r\n\r\n") != NULL) {
				return true;
			}
			continue;
		}
		if (n == 0) {
			break;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ev_run(loop, EVRUN_ONCE);
			continue;
		}
		break;
	}
	ev_timer_stop(loop, &w_timeout);
	buf[off] = '\0';
	return strstr(buf, "\r\n\r\n") != NULL;
}

static bool send_response(
	const int fd, const char *status_line, const char *content_type,
	const char *connection, const void *body, const size_t body_len)
{
	char hdr[1024];
	int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %s\r\n", status_line);
	if (n <= 0 || (size_t)n >= sizeof(hdr)) {
		return false;
	}
	size_t off = (size_t)n;
	if (content_type != NULL) {
		n = snprintf(
			hdr + off, sizeof(hdr) - off, "Content-Type: %s\r\n",
			content_type);
		if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
			return false;
		}
		off += (size_t)n;
	}
	if (connection != NULL) {
		n = snprintf(
			hdr + off, sizeof(hdr) - off, "Connection: %s\r\n",
			connection);
		if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
			return false;
		}
		off += (size_t)n;
	}
	n = snprintf(
		hdr + off, sizeof(hdr) - off, "Content-Length: %zu\r\n\r\n",
		body_len);
	if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
		return false;
	}
	off += (size_t)n;
	if (!write_all(fd, hdr, off)) {
		return false;
	}
	if (body_len > 0) {
		return write_all(fd, body, body_len);
	}
	return true;
}

static struct dialreq *new_test_dialreq(void)
{
	return calloc(1, sizeof(struct dialreq));
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub dialer error";
}

void dialer_init(struct dialer *restrict d, const struct dialer_cb *callback)
{
	d->finish_cb = *callback;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver)
{
	(void)req;
	(void)conf;
	(void)resolver;
	S.dialer_do_calls++;
	d->err = S.dialer_err;
	d->syserr = S.dialer_syserr;
	if (S.dialer_defer) {
		S.pending_loop = loop;
		S.pending_dialer = d;
		return;
	}
	d->finish_cb.func(loop, d->finish_cb.data, S.dialer_result_fd);
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

int conn_cache_get(struct ev_loop *loop, const struct dialreq *restrict req)
{
	(void)loop;
	(void)req;
	S.conn_cache_get_calls++;
	return S.conn_cache_get_fd;
}

void conn_cache_put(
	struct ev_loop *loop, const int fd,
	const struct dialreq *restrict dialreq)
{
	(void)loop;
	S.conn_cache_put_calls++;
	S.conn_cache_put_fd = fd;
	S.conn_cache_put_req = dialreq;
	if (S.close_fd_on_conn_put) {
		(void)close(fd);
	}
}

bool check_rpcall_mime(char *mime_type)
{
	if (mime_type == NULL) {
		return false;
	}
	return strcasecmp(mime_type, MIME_RPCALL) == 0;
}

T_DECLARE_CASE(rpcall_success_returns_stream)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(ctx != NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.errmsg[0] == '\0');
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, sizeof(rsp_body) - 1);
	T_EXPECT_MEMEQ(out.stream_buf, rsp_body, sizeof(rsp_body) - 1);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(invoke_uses_invoke_path)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req = NULL;
	struct fd_closed_ctx closed_ctx = { 0 };
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	api_client_invoke(
		loop, req, payload, sizeof(payload) - 1, &test_conf, NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/invoke HTTP/1.1") != NULL);
	T_CHECK(send_response(sv[1], "204 No Content", NULL, "close", NULL, 0));
	closed_ctx.fd = sv[1];
	T_CHECK(test_wait_until(
		loop, fd_closed_predicate, &closed_ctx,
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT_EQ(S.conn_cache_put_calls, 0);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_unsupported_content_type)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "x";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(send_response(
		sv[1], "200 OK", "text/plain", "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "unsupported content-type");
	T_EXPECT(!out.has_stream);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_dialer_failure)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_result_fd = -1;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_SHORT_SEC));
	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "connection failed");
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_timeout)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	test_conf.timeout = 0.005;
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_LONG_SEC));
	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "timeout");

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_http_error_status_line)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(send_response(sv[1], "404 Not Found", NULL, "close", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT(strstr(out.errmsg, "404") != NULL);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_structured_error_body)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "backend failed";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(send_response(
		sv[1], "500 Internal Server Error", MIME_RPCALL, "close",
		rsp_body, sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, sizeof(rsp_body) - 1);
	T_EXPECT_STREQ(out.errmsg, rsp_body);
	T_EXPECT(!out.has_stream);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(cancel_during_connect_calls_dialer_cancel)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_defer = true;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(ctx != NULL);
	api_client_cancel(loop, ctx);
	T_EXPECT_EQ(S.dialer_cancel_calls, 1);
	T_EXPECT(!out.called);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connection_keep_alive_recycled)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(S.conn_cache_put_calls, 1);
	T_EXPECT_EQ(S.conn_cache_put_fd, sv[0]);
	T_EXPECT(S.conn_cache_put_req == req);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connection_close_not_recycled)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &test_conf,
		NULL));
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "close", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(S.conn_cache_put_calls, 0);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, rpcall_success_returns_stream);
	T_RUN_CASE(t, invoke_uses_invoke_path);
	T_RUN_CASE(t, rpcall_unsupported_content_type);
	T_RUN_CASE(t, rpcall_dialer_failure);
	T_RUN_CASE(t, rpcall_timeout);
	T_RUN_CASE(t, rpcall_http_error_status_line);
	T_RUN_CASE(t, rpcall_structured_error_body);
	T_RUN_CASE(t, cancel_during_connect_calls_dialer_cancel);
	T_RUN_CASE(t, connection_keep_alive_recycled);
	T_RUN_CASE(t, connection_close_not_recycled);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else

int main(void)
{
	return 0;
}

#endif
