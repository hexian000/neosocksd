/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socks.h"

#include "conf.h"
#include "dialer.h"
#include "proto/socks.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * These tests focus on protocol parsing paths in socks.c. Dependencies for
 * dialing and transfer are stubbed so parser behavior can be asserted in
 * isolation.
 */

/**
 * Test-only definition of struct globals (removed from util.h during refactoring).
 * Used to stub G.conf and G.ruleset for test initialization.
 */
struct globals {
	const struct config *conf;
	struct resolver *resolver;
	struct ruleset *ruleset;
	struct server *server;
	struct dialreq *basereq;
};

struct globals G = { 0 };

static struct config test_conf = {
	.timeout = 1.0,
	.auth_required = false,
	.bidir_timeout = false,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.016;
static const ev_tstamp TEST_WAIT_TIMEOUT_SEC = 0.128;

static ev_tstamp test_timeout_wait_window(const ev_tstamp timeout_sec)
{
	ev_tstamp wait_sec = timeout_sec * 4.0;
	if (wait_sec < TEST_WAIT_SHORT_SEC) {
		wait_sec = TEST_WAIT_SHORT_SEC;
	}
	return wait_sec;
}

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

enum stub_dialer_mode {
	STUB_DIALER_NONE,
	STUB_DIALER_FAIL,
	STUB_DIALER_SUCCESS,
};

enum stub_transfer_mode {
	STUB_TRANSFER_NONE,
	STUB_TRANSFER_CONNECTED,
	STUB_TRANSFER_FINISHED,
};

enum stub_ruleset_mode {
	STUB_RULESET_FAIL,
	STUB_RULESET_ASYNC_OK,
};

static struct {
	bool dialreq_available;

	enum stub_dialer_mode dialer_mode;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int dialer_success_fd;
	size_t dialer_cancel_count;

	enum stub_transfer_mode transfer_mode;

	enum stub_ruleset_mode ruleset_mode;
	struct ruleset_callback *ruleset_pending_cb;
	size_t ruleset_cancel_count;
} STUB = {
	.dialreq_available = false,
	.dialer_mode = STUB_DIALER_NONE,
	.dialer_err = DIALER_OK,
	.dialer_syserr = 0,
	.dialer_success_fd = -1,
	.transfer_mode = STUB_TRANSFER_NONE,
	.ruleset_mode = STUB_RULESET_FAIL,
	.ruleset_pending_cb = NULL,
	.ruleset_cancel_count = 0,
};

static int stub_ruleset_state_tag = 0;

static void stub_reset(void)
{
	STUB.dialreq_available = false;
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.dialer_err = DIALER_OK;
	STUB.dialer_syserr = 0;
	STUB.dialer_success_fd = -1;
	STUB.dialer_cancel_count = 0;
	STUB.transfer_mode = STUB_TRANSFER_NONE;
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	STUB.ruleset_pending_cb = NULL;
	STUB.ruleset_cancel_count = 0;
	G.ruleset = NULL;
}

/**
 * Initialize server struct for testing.
 * Sets minimal required fields so production code can access conf/resolver/etc.
 */
static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->ruleset = G.ruleset;
	s->basereq = NULL;
}

static void finish_ruleset(struct ev_loop *loop)
{
	if (STUB.ruleset_pending_cb == NULL) {
		return;
	}
	ev_feed_event(loop, &STUB.ruleset_pending_cb->w_finish, EV_CUSTOM);
	STUB.ruleset_pending_cb = NULL;
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	(void)base;
	if (!STUB.dialreq_available) {
		return NULL;
	}
	if (num_proxy != 0) {
		return NULL;
	}
	struct dialreq *req = malloc(sizeof(*req));
	if (req == NULL) {
		return NULL;
	}
	memset(req, 0, sizeof(*req));
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	(void)req;
	(void)proxy_uri;
	(void)urilen;
	return false;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	(void)addr;
	(void)csv;
	return NULL;
}

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	(void)s;
	(void)maxlen;
	(void)r;
	return -1;
}

void dialreq_free(struct dialreq *req)
{
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	(void)addr;
	(void)s;
	(void)len;
	return false;
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	(void)addr;
	(void)sa;
	(void)len;
	return false;
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	*dst = *src;
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	(void)addr;
	if (s != NULL && maxlen > 0) {
		(void)snprintf(s, maxlen, "(stub)");
	}
	return 6;
}

void dialer_init(struct dialer *restrict d, const struct dialer_cb *callback)
{
	d->finish_cb = *callback;
	d->err = DIALER_OK;
	d->syserr = 0;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver)
{
	(void)req;
	(void)conf;
	(void)resolver;

	switch (STUB.dialer_mode) {
	case STUB_DIALER_NONE:
		return;
	case STUB_DIALER_FAIL:
		d->err = STUB.dialer_err;
		d->syserr = STUB.dialer_syserr;
		d->finish_cb.func(loop, d->finish_cb.data, -1);
		return;
	case STUB_DIALER_SUCCESS: {
		int fd = STUB.dialer_success_fd;
		if (fd < 0) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
		}
		if (fd < 0) {
			d->err = DIALER_ERR_SYSTEM;
			d->syserr = errno;
			d->finish_cb.func(loop, d->finish_cb.data, -1);
			return;
		}
		d->err = DIALER_OK;
		d->syserr = 0;
		d->finish_cb.func(loop, d->finish_cb.data, fd);
		return;
	}
	default:
		return;
	}
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	(void)d;
	(void)loop;
	STUB.dialer_cancel_count++;
}

void transfer_init(
	struct transfer *restrict t, const struct transfer_state_cb *callback,
	const int src_fd, const int dst_fd, uintmax_t *byt_transferred,
	const bool is_uplink, const bool use_splice)
{
	t->state = XFER_INIT;
	t->state_cb = *callback;
	t->src_fd = src_fd;
	t->dst_fd = dst_fd;
	t->byt_transferred = byt_transferred;
	t->is_uplink = is_uplink;
	t->use_splice = use_splice;
}

void transfer_start(struct ev_loop *restrict loop, struct transfer *restrict t)
{
	switch (STUB.transfer_mode) {
	case STUB_TRANSFER_NONE:
		return;
	case STUB_TRANSFER_CONNECTED:
		t->state = XFER_CONNECTED;
		break;
	case STUB_TRANSFER_FINISHED:
		t->state = XFER_FINISHED;
		break;
	default:
		return;
	}
	t->state_cb.func(loop, t->state_cb.data);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	(void)loop;
	(void)t;
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
	STUB.ruleset_cancel_count++;
}

static bool ruleset_stub_resolve(
	struct ruleset_state **state, struct ruleset_callback *callback)
{
	if (STUB.ruleset_mode == STUB_RULESET_FAIL) {
		return false;
	}
	if (STUB.ruleset_mode != STUB_RULESET_ASYNC_OK) {
		return false;
	}

	callback->request.req = dialreq_new(NULL, 0);
	if (callback->request.req == NULL) {
		return false;
	}
	*state = (struct ruleset_state *)&stub_ruleset_state_tag;
	STUB.ruleset_pending_cb = callback;
	return true;
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)username;
	(void)password;
	return ruleset_stub_resolve(state, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)username;
	(void)password;
	return ruleset_stub_resolve(state, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)username;
	(void)password;
	return ruleset_stub_resolve(state, callback);
}

static int write_all(const int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		const ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
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

static ssize_t recv_after_readable(
	struct ev_loop *loop, const int fd, void *buf, const size_t len,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		const ssize_t n = recv_nowait(fd, buf, len);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			ev_run(loop, EVRUN_ONCE);
			continue;
		}
		ev_timer_stop(loop, &w_timeout);
		return n;
	}
	ev_timer_stop(loop, &w_timeout);
	return recv_nowait(fd, buf, len);
}

static void test_run_for(struct ev_loop *loop, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
}

static bool
test_step_timed_out(struct ev_loop *loop, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_run(loop, EVRUN_ONCE);
	ev_timer_stop(loop, &w_timeout);
	return watchdog.fired;
}

static void drive_loop(struct ev_loop *loop)
{
	for (int_fast32_t i = 0; i < 16; i++) {
		if (test_step_timed_out(loop, TEST_WAIT_SHORT_SEC)) {
			break;
		}
	}
}

static void serve_payload(
	struct ev_loop *loop, struct server *restrict s,
	const unsigned char *restrict payload, const size_t payload_len,
	int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	socks_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	T_CHECK(write_all(sv[1], payload, payload_len) == 0);

	*peer_fd = sv[1];
}

static void serve_payload_split(
	struct ev_loop *loop, struct server *restrict s,
	const unsigned char *restrict first, const size_t first_len,
	const unsigned char *restrict second, const size_t second_len,
	int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	socks_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	if (first_len > 0) {
		T_CHECK(write_all(sv[1], first, first_len) == 0);
	}
	drive_loop(loop);
	if (second_len > 0) {
		T_CHECK(write_all(sv[1], second, second_len) == 0);
	}

	*peer_fd = sv[1];
}

T_DECLARE_CASE(invalid_version_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x06,
		0x00,
		0x00,
		0x00,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[16];
		const ssize_t n = recv_nowait(peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n == 0 || (n < 0 && errno == EAGAIN));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_unsupported_command_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_CMDNOSUPPORT);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_unsupported_atyp_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_ATYPNOSUPPORT);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_userpass_empty_username_fails)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x02, 0x01, 0x00, 0x00,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_USERPASS);
		T_EXPECT_EQ(rsp[2], 0x01);
		T_EXPECT_EQ(rsp[3], 0x01);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_no_acceptable_auth_method)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05,
		0x01,
		0x00,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 2);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOACCEPTABLE);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_valid_ipv4_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_userpass_domain_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x02, 0x01, 0x04, 'u',  's',  'e',	'r',  0x04, 'p',
		'a',  's',  's',  0x05, 0x01, 0x00, 0x03, 0x0b, 'e',  'x',  'a',
		'm',  'p',  'l',  'e',	'.',  'c',  'o',  'm',	0x01, 0xbb,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_USERPASS);
		T_EXPECT_EQ(rsp[2], 0x01);
		T_EXPECT_EQ(rsp[3], 0x00);
		T_EXPECT_EQ(rsp[4], SOCKS5);
		T_EXPECT_EQ(rsp[5], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_valid_ipv6_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04, 0x20, 0x01,
		0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x35,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4_long_userid_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	unsigned char req[SOCKS4_HDR_LEN + 300];

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	memset(req, 'A', sizeof(req));
	req[0] = SOCKS4;
	req[1] = SOCKS4CMD_CONNECT;
	req[2] = 0x00;
	req[3] = 0x50;
	req[4] = 0x01;
	req[5] = 0x02;
	req[6] = 0x03;
	req[7] = 0x04;

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4_valid_connect_rejected_when_dialreq_unavailable)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x00,	0x50,
		0x7f,	0x00,
		0x00,	0x01,
		'u',	's',
		'e',	'r',
		0x00,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4a_domain_connect_dialer_fail_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x01,	0xbb,
		0x00,	0x00,
		0x00,	0x01,
		'u',	0x00,
		'a',	'.',
		'c',	'o',
		'm',	0x00,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = EHOSTUNREACH;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_split_payload_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char part1[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00,
	};
	const unsigned char part2[] = {
		0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = ECONNREFUSED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload_split(
		loop, &s, part1, sizeof(part1), part2, sizeof(part2), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_CONNREFUSED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_connect_timeout_rsp_ttl_expired)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_NONE;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 0.02;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);
	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));

	{
		unsigned char rsp[32];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_TTLEXPIRED);
	}
	T_EXPECT(STUB.dialer_cancel_count > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_ruleset_reject_rsp_fail)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	G.ruleset = (struct ruleset *)&test_conf;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_server_init(&s);
	s.ruleset = (struct ruleset *)&test_conf;

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
}

T_DECLARE_CASE(socks5_ruleset_async_then_dialer_fail_noallowed)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_AUTH;
	STUB.dialer_syserr = 0;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_server_init(&s);
	s.ruleset = (struct ruleset *)&test_conf;

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);
	finish_ruleset(loop);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_NOALLOWED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
}

T_DECLARE_CASE(socks5_dialer_system_error_netunreach)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_SYSTEM;
	STUB.dialer_syserr = ENETUNREACH;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_NETUNREACH);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_success_transfer_finished)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	STUB.transfer_mode = STUB_TRANSFER_FINISHED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_conf.bidir_timeout = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.bidir_timeout = false;
}

T_DECLARE_CASE(socks5_dialer_success_connected_transition)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	STUB.transfer_mode = STUB_TRANSFER_CONNECTED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.timeout = 1.0;
	test_conf.bidir_timeout = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.bidir_timeout = false;
}

T_DECLARE_CASE(socks5_bind_disabled_cmdnosupport)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth + BIND request (IPv4 0.0.0.0:0) */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_CMDNOSUPPORT);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_udp_disabled_cmdnosupport)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth + UDP ASSOCIATE request (IPv4 0.0.0.0:0) */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_CMDNOSUPPORT);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_first_reply_succeeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		/* auth(2) + BIND first reply: hdr(4) + IPv4(4) + port(2) = 12 */
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[4], 0x00); /* reserved */
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_bind = false;
}

T_DECLARE_CASE(socks5_bind_full_flow)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int connector_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	STUB.transfer_mode = STUB_TRANSFER_FINISHED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_conf.timeout = 1.0;
	test_conf.bidir_timeout = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	/* auth(2) + BIND first reply hdr(4) + IPv4(4) + port(2) = 12 bytes */
	unsigned char rsp[64];
	ssize_t n = recv_after_readable(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(n >= 12);
	T_EXPECT_EQ(rsp[2], SOCKS5);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);

	/* Extract the port from the first BIND response (big-endian at rsp[10]) */
	in_port_t bind_port;
	memcpy(&bind_port, rsp + 10, sizeof(bind_port));

	connector_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(connector_fd >= 0);
	{
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = bind_port,
		};
		T_CHECK(connect(connector_fd, (const struct sockaddr *)&sa,
				sizeof(sa)) == 0);
	}

	drive_loop(loop);

	/* BIND second reply: hdr(4) + IPv4(4) + port(2) = 10 bytes */
	unsigned char rsp2[32];
	const ssize_t n2 = recv_after_readable(
		loop, peer_fd, rsp2, sizeof(rsp2), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(n2 >= 10);
	T_EXPECT_EQ(rsp2[0], SOCKS5);
	T_EXPECT_EQ(rsp2[1], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp2[3], SOCKS5ADDR_IPV4);

	T_CHECK(close(connector_fd) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_bind = false;
	test_conf.bidir_timeout = false;
}

T_DECLARE_CASE(socks5_bind_mismatch_allows)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int connector_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		127,  0,    0,	  2,	0x00,		0x00,
	};

	stub_reset();
	STUB.transfer_mode = STUB_TRANSFER_FINISHED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_conf.timeout = 1.0;
	test_conf.bidir_timeout = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	ssize_t n = recv_after_readable(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(n >= 12);
	T_EXPECT_EQ(rsp[2], SOCKS5);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);

	in_port_t bind_port;
	memcpy(&bind_port, rsp + 10, sizeof(bind_port));

	connector_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(connector_fd >= 0);
	{
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = bind_port,
		};
		T_CHECK(connect(connector_fd, (const struct sockaddr *)&sa,
				sizeof(sa)) == 0);
	}

	drive_loop(loop);

	unsigned char rsp2[32];
	const ssize_t n2 = recv_after_readable(
		loop, peer_fd, rsp2, sizeof(rsp2), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(n2 >= 10);
	T_EXPECT_EQ(rsp2[0], SOCKS5);
	T_EXPECT_EQ(rsp2[1], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp2[3], SOCKS5ADDR_IPV4);

	T_CHECK(close(connector_fd) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_bind = false;
	test_conf.bidir_timeout = false;
}

T_DECLARE_CASE(socks5_bind_timeout_ttlexpired)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_conf.timeout = 0.02;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 14);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		/* First BIND reply: SUCCEEDED */
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		/* Timeout reply: TTLEXPIRED */
		T_EXPECT_EQ(rsp[12], SOCKS5);
		T_EXPECT_EQ(rsp[13], SOCKS5RSP_TTLEXPIRED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_bind = false;
	test_conf.timeout = 1.0;
}

T_DECLARE_CASE(socks5_udp_first_reply_succeeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		/* auth(2) + UDP reply: hdr(4) + IPv4(4) + port(2) = 12 */
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[4], 0x00); /* reserved */
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_udp = false;
}

T_DECLARE_CASE(socks5_udp_relay_roundtrip)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	/* Read UDP relay port from the SOCKS5 response */
	unsigned char rsp[64];
	const ssize_t nrsp = recv_after_readable(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	/* Create a target UDP socket bound to 127.0.0.1:0 */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Create client UDP socket bound to 127.0.0.1:0 */
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	/* Build SOCKS5 UDP packet: RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+port(2)+data */
	unsigned char udp_pkt[10 + 5]; /* header + "hello" */
	udp_pkt[0] = 0;
	udp_pkt[1] = 0; /* RSV */
	udp_pkt[2] = 0; /* FRAG */
	udp_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(udp_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(udp_pkt + 8, &target_bound.sin_port, 2);
	memcpy(udp_pkt + 10, "hello", 5);

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));

	drive_loop(loop);

	/* Check that target received the raw data "hello" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}

	/* Target sends reply "world" back to relay */
	T_CHECK(sendto(target_udp, "world", 5, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 5);

	drive_loop(loop);

	/* Client should receive SOCKS5-wrapped "world" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		/* RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+port(2)+data(5) = 15 */
		T_EXPECT(n == 15);
		T_EXPECT_EQ(buf[0], 0x00);
		T_EXPECT_EQ(buf[1], 0x00);
		T_EXPECT_EQ(buf[2], 0x00);
		T_EXPECT_EQ(buf[3], SOCKS5ADDR_IPV4);
		T_EXPECT(memcmp(buf + 10, "world", 5) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_udp = false;
}

T_DECLARE_CASE(socks5_udp_tcp_close_teardown)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_after_readable(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	}

	/* Closing the TCP control connection should tear down the relay */
	T_CHECK(close(peer_fd) == 0);
	drive_loop(loop);

	/* Verify that the server session counter is back to zero */
	T_EXPECT(s.stats.num_sessions == 0);

	ev_loop_destroy(loop);
	test_conf.socks5_udp = false;
}

T_DECLARE_CASE(socks5_udp_frag_two_parts)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_after_readable(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	/* Bind a target UDP socket */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Bind a client UDP socket */
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Fragment 1 (FRAG=0x01): "Hello " */
	unsigned char frag1[10 + 6];
	frag1[0] = 0;
	frag1[1] = 0; /* RSV */
	frag1[2] = 0x01; /* FRAG: first, more to come */
	frag1[3] = SOCKS5ADDR_IPV4;
	memcpy(frag1 + 4, &target_bound.sin_addr, 4);
	memcpy(frag1 + 8, &target_bound.sin_port, 2);
	memcpy(frag1 + 10, "Hello ", 6);
	T_CHECK(sendto(client_udp, frag1, sizeof(frag1), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag1));

	drive_loop(loop);

	/* Target should have received nothing yet */
	{
		unsigned char buf[32];
		T_EXPECT(recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT) < 0);
	}

	/* Fragment 2 (FRAG=0x82): "World" — last fragment */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "World", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));

	drive_loop(loop);

	/* Target must now receive the reassembled payload "Hello World" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 11);
		T_EXPECT(memcmp(buf, "Hello World", 11) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_udp = false;
}

T_DECLARE_CASE(socks5_udp_frag_discard_out_of_order)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_conf.timeout = 1.0;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_after_readable(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_TIMEOUT_SEC);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Send FRAG=2 without a preceding FRAG=1: out-of-order, must discard */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "oops!", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));

	drive_loop(loop);

	/* Target must receive nothing */
	{
		unsigned char buf[32];
		T_EXPECT(recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT) < 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	test_conf.socks5_udp = false;
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, invalid_version_rejected);
	T_RUN_CASE(t, socks5_unsupported_command_rsp);
	T_RUN_CASE(t, socks5_unsupported_atyp_rsp);
	T_RUN_CASE(t, socks5_userpass_empty_username_fails);
	T_RUN_CASE(t, socks5_no_acceptable_auth_method);
	T_RUN_CASE(t, socks5_valid_ipv4_request_connect_fail_rsp);
	T_RUN_CASE(t, socks5_userpass_domain_request_connect_fail_rsp);
	T_RUN_CASE(t, socks5_valid_ipv6_request_connect_fail_rsp);
	T_RUN_CASE(t, socks4_long_userid_rejected);
	T_RUN_CASE(t, socks4_valid_connect_rejected_when_dialreq_unavailable);
	T_RUN_CASE(t, socks4a_domain_connect_dialer_fail_rejected);
	T_RUN_CASE(t, socks5_split_payload_connect_fail_rsp);
	T_RUN_CASE(t, socks5_connect_timeout_rsp_ttl_expired);
	T_RUN_CASE(t, socks5_ruleset_reject_rsp_fail);
	T_RUN_CASE(t, socks5_ruleset_async_then_dialer_fail_noallowed);
	T_RUN_CASE(t, socks5_dialer_system_error_netunreach);
	T_RUN_CASE(t, socks5_dialer_success_transfer_finished);
	T_RUN_CASE(t, socks5_dialer_success_connected_transition);
	T_RUN_CASE(t, socks5_bind_disabled_cmdnosupport);
	T_RUN_CASE(t, socks5_udp_disabled_cmdnosupport);
	T_RUN_CASE(t, socks5_bind_first_reply_succeeded);
	T_RUN_CASE(t, socks5_bind_full_flow);
	T_RUN_CASE(t, socks5_bind_mismatch_allows);
	T_RUN_CASE(t, socks5_bind_timeout_ttlexpired);
	T_RUN_CASE(t, socks5_udp_first_reply_succeeded);
	T_RUN_CASE(t, socks5_udp_relay_roundtrip);
	T_RUN_CASE(t, socks5_udp_tcp_close_teardown);
	T_RUN_CASE(t, socks5_udp_frag_two_parts);
	T_RUN_CASE(t, socks5_udp_frag_discard_out_of_order);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
