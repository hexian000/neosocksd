/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for http_client.c; mocked: dialer. */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "util.h"

#include "proto/http.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - dialer/dialreq stubs and shared fixtures.
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 0.2,
};

static struct {
	int dialer_result_fd;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialreq_free_calls;
} S = {
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.dialreq_free_calls = 0,
};

static void stub_reset(void)
{
	S.dialer_result_fd = -1;
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

/* ---- callback capture ---- */

struct cb_result {
	bool called;
	const char *errmsg;
	size_t errlen;
};

static void capture_cb(
	struct ev_loop *loop, void *data, const char *errmsg,
	const size_t errlen, struct http_conn *conn)
{
	struct cb_result *restrict r = data;
	(void)loop;
	(void)conn;
	r->called = true;
	r->errmsg = errmsg;
	r->errlen = errlen;
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
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
