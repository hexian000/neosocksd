/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "proto/http.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"
#include "util.h"

#include "os/clock.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct config test_conf = {
	.timeout = 1.0,
};

static const ev_tstamp TEST_WAIT_CLOSE_SEC = 0.016;
static const ev_tstamp TEST_WAIT_RECV_SEC = 0.128;

static struct resolver_stats resolver_stub_stats = {
	.num_query = 7,
	.num_success = 5,
};

const struct resolver_stats *resolver_stats(const struct resolver *restrict r)
{
	(void)r;
	return &resolver_stub_stats;
}

void server_stats(
	const struct server *restrict s, struct server_stats *restrict out)
{
	*out = s->stats;
	out->num_accept = 0;
	out->num_serve = 0;
	for (size_t i = 0; i < s->num_listeners; i++) {
		const struct listener_stats *restrict lst =
			&s->listeners[i].stats;
		out->num_accept += lst->num_accept;
		out->num_serve += lst->num_serve;
	}
	out->num_sessions = s->num_sessions;
	out->byt_up = s->byt_up;
	out->byt_down = s->byt_down;
}

#if WITH_SPLICE
void pipe_shrink(size_t count)
{
	(void)count;
}
#endif

#if WITH_RULESET
static struct {
	bool invoke_ok;
	bool update_ok;
	bool gc_ok;
	bool rpcall_ok;
	bool rpcall_null_result;
	bool rpcall_auto_finish;
	bool stats_ok;

	const char *errstr;
	size_t errlen;
	const char *stats_str;
	size_t stats_len;
	const char *rpcall_result;
	size_t rpcall_resultlen;

	size_t vmstats_count;
	struct ruleset_vmstats vmstats_before;
	struct ruleset_vmstats vmstats_after;

	struct ruleset_state *rpcstate;
	struct ruleset_callback *pending_rpcall;
	size_t cancel_count;
	size_t stats_call_count;
	bool metrics_ok;
	const char *metrics_str;
	size_t metrics_len;
	size_t metrics_call_count;
	struct ev_loop *loop;
} RS = {
	.invoke_ok = true,
	.update_ok = true,
	.gc_ok = true,
	.rpcall_ok = true,
	.rpcall_null_result = false,
	.rpcall_auto_finish = false,
	.stats_ok = true,
	.errstr = "ruleset error",
	.errlen = sizeof("ruleset error") - 1,
	.stats_str = "ruleset stats\n",
	.stats_len = sizeof("ruleset stats\n") - 1,
	.metrics_ok = false,
	.metrics_str = "custom_metric 1\n",
	.metrics_len = sizeof("custom_metric 1\n") - 1,
	.rpcall_result = "ok",
	.rpcall_resultlen = 2,
	.vmstats_count = 0,
	.vmstats_before = {
		.num_object = 128,
		.byt_allocated = 1024 * 1024,
		.num_events = 0,
	},
	.vmstats_after = {
		.num_object = 64,
		.byt_allocated = 512 * 1024,
		.num_events = 0,
	},
	.rpcstate = NULL,
	.pending_rpcall = NULL,
	.cancel_count = 0,
	.stats_call_count = 0,
	.loop = NULL,
};

static int ruleset_state_tag = 0;

static void reset_ruleset_stub(void)
{
	RS.invoke_ok = true;
	RS.update_ok = true;
	RS.gc_ok = true;
	RS.rpcall_ok = true;
	RS.rpcall_null_result = false;
	RS.rpcall_auto_finish = false;
	RS.stats_ok = true;
	RS.errstr = "ruleset error";
	RS.errlen = sizeof("ruleset error") - 1;
	RS.stats_str = "ruleset stats\n";
	RS.stats_len = sizeof("ruleset stats\n") - 1;
	RS.rpcall_result = "ok";
	RS.rpcall_resultlen = 2;
	RS.vmstats_count = 0;
	RS.vmstats_before = (struct ruleset_vmstats){
		.num_object = 128,
		.byt_allocated = 1024 * 1024,
		.num_events = 0,
	};
	RS.vmstats_after = (struct ruleset_vmstats){
		.num_object = 64,
		.byt_allocated = 512 * 1024,
		.num_events = 0,
	};
	RS.rpcstate = NULL;
	RS.pending_rpcall = NULL;
	RS.cancel_count = 0;
	RS.stats_call_count = 0;
	RS.metrics_ok = false;
	RS.metrics_str = "custom_metric 1\n";
	RS.metrics_len = sizeof("custom_metric 1\n") - 1;
	RS.metrics_call_count = 0;
	RS.loop = NULL;
}

static void finish_rpcall(struct ev_loop *loop)
{
	if (RS.pending_rpcall == NULL) {
		return;
	}
	ev_feed_event(loop, &RS.pending_rpcall->w_finish, EV_CUSTOM);
	RS.pending_rpcall = NULL;
}

const char *
ruleset_geterror(const struct ruleset *restrict r, size_t *restrict len)
{
	(void)r;
	if (len != NULL) {
		*len = RS.errlen;
	}
	return RS.errstr;
}

bool ruleset_invoke(struct ruleset *restrict r, struct stream *code)
{
	(void)r;
	(void)code;
	return RS.invoke_ok;
}

bool ruleset_update(
	struct ruleset *restrict r, const char *restrict modname,
	const char *restrict chunkname, struct stream *code)
{
	(void)r;
	(void)modname;
	(void)chunkname;
	(void)code;
	return RS.update_ok;
}

bool ruleset_gc(struct ruleset *restrict r)
{
	(void)r;
	return RS.gc_ok;
}

bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct stream *code, struct ruleset_callback *callback)
{
	(void)r;
	(void)code;
	if (!RS.rpcall_ok) {
		return false;
	}
	if (RS.rpcall_null_result) {
		callback->rpcall.result = NULL;
		callback->rpcall.resultlen = 0;
	} else {
		callback->rpcall.result = RS.rpcall_result;
		callback->rpcall.resultlen = RS.rpcall_resultlen;
	}
	RS.rpcstate = (struct ruleset_state *)&ruleset_state_tag;
	*state = RS.rpcstate;
	if (RS.rpcall_auto_finish && RS.loop != NULL) {
		ev_feed_event(RS.loop, &callback->w_finish, EV_CUSTOM);
		return true;
	}
	RS.pending_rpcall = callback;
	return true;
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
	RS.cancel_count++;
}

void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s)
{
	(void)r;
	if (RS.vmstats_count == 0) {
		*s = RS.vmstats_before;
	} else {
		*s = RS.vmstats_after;
	}
	RS.vmstats_count++;
}

const char *ruleset_stats(
	struct ruleset *restrict r, double dt, const char *restrict query,
	size_t *len)
{
	(void)r;
	(void)dt;
	(void)query;
	RS.stats_call_count++;
	if (!RS.stats_ok) {
		if (len != NULL) {
			*len = RS.errlen;
		}
		return NULL;
	}
	if (len != NULL) {
		*len = RS.stats_len;
	}
	return RS.stats_str;
}

const char *ruleset_metrics(struct ruleset *restrict r, size_t *len)
{
	(void)r;
	RS.metrics_call_count++;
	if (!RS.metrics_ok) {
		return NULL;
	}
	if (len != NULL) {
		*len = RS.metrics_len;
	}
	return RS.metrics_str;
}
#endif

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

static bool find_bytes(
	const unsigned char *restrict haystack, const size_t haystack_len,
	const char *restrict needle)
{
	const size_t needle_len = strlen(needle);
	if (needle_len == 0 || haystack_len < needle_len) {
		return false;
	}
	for (size_t i = 0; i + needle_len <= haystack_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
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

static bool ruleset_rpcall_pending(void *data)
{
	(void)data;
	return RS.pending_rpcall != NULL;
}

static ssize_t recv_all_with_timeout(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	size_t off = 0;
	int_fast32_t idle_after_data = 0;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && off < cap) {
		const ssize_t n = recv(fd, buf + off, cap - off, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (off > 0) {
					idle_after_data++;
					if (idle_after_data >= 2) {
						break;
					}
				}
				ev_run(loop, EVRUN_ONCE);
				continue;
			}
			ev_timer_stop(loop, &w_timeout);
			return -1;
		}
		if (n == 0) {
			break;
		}
		off += (size_t)n;
		idle_after_data = 0;
	}
	ev_timer_stop(loop, &w_timeout);
	return (ssize_t)off;
}

static void init_server_pair(
	struct server *restrict api, struct server *restrict core,
	struct ev_loop *loop)
{
	*api = (struct server){ 0 };
	*core = (struct server){ 0 };
	api->loop = loop;
	api->conf = &test_conf;
	api->data = core;
	api->stats.started = clock_monotonic_ns() - 500000000;
	core->conf = &test_conf;
	core->resolver = (struct resolver *)&resolver_stub_stats;
	core->stats.started = api->stats.started;
	core->num_listeners = 1;
	core->listeners[0].stats.num_accept = 9;
	core->listeners[0].stats.num_serve = 8;
	core->stats.num_request = 13;
	core->stats.num_success = 11;
	core->byt_up = 4096;
	core->byt_down = 8192;
#if WITH_RULESET
	api->ruleset = NULL;
	core->ruleset = NULL;
#endif
}

static void init_unified_server(struct server *restrict s, struct ev_loop *loop)
{
	*s = (struct server){ 0 };
	s->loop = loop;
	s->conf = &test_conf;
	s->data = s;
	s->resolver = (struct resolver *)&resolver_stub_stats;
	s->stats.started = clock_monotonic_ns() - 500000000;
	s->num_listeners = 1;
	s->listeners[0].stats.num_accept = 9;
	s->listeners[0].stats.num_serve = 8;
	s->stats.num_request = 13;
	s->stats.num_success = 11;
	s->byt_up = 4096;
	s->byt_down = 8192;
#if WITH_RULESET
	s->ruleset = NULL;
#endif
}

static void start_api(
	struct server *restrict api, struct ev_loop *loop,
	int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_cloexec(sv[0]) == 0);
	T_CHECK(socket_set_nonblock(sv[0]) == 0);
	T_CHECK(socket_set_cloexec(sv[1]) == 0);
	T_CHECK(socket_set_nonblock(sv[1]) == 0);
	api_serve(api, loop, sv[0], (const struct sockaddr *)&sa);
	*peer_fd = sv[1];
}

static bool send_request(const int peer_fd, const char *restrict req)
{
	return write_all(peer_fd, req, strlen(req)) == 0;
}

static bool assert_status(
	const unsigned char *restrict rsp, const size_t n, const char *code)
{
	return find_bytes(rsp, n, code);
}

T_DECLARE_CASE(healthy_keepalive_reuse_connection)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /healthy HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Connection: keep-alive\r\n"));
	}

	T_CHECK(send_request(peer_fd, "GET /healthy HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(healthy_connection_close_header)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\n"
			 "Connection: close\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Connection: close\r\n"));
	}

	test_run_for(loop, TEST_WAIT_CLOSE_SEC);
	{
		const ssize_t n = recv(peer_fd, rsp, sizeof(rsp), MSG_DONTWAIT);
		T_EXPECT(
			n == 0 ||
			(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(api_stats_do_not_pollute_proxy_stats_in_unified_server)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /healthy HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_EXPECT_EQ(s.stats.num_request, 13);
	T_EXPECT_EQ(s.stats.num_success, 11);
	T_EXPECT_EQ(s.stats.num_api_request, 1);
	T_EXPECT_EQ(s.stats.num_api_success, 1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(metrics_unsupported_accept_encoding_and_te_returns_200)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
	start_api(&s, loop, &peer_fd);

	/* Prometheus sends Accept-Encoding: gzip and TE: trailers — both
	 * are valid headers whose values the server simply does not support.
	 * The API endpoint must respond 200, not 400. */
	T_CHECK(send_request(
		peer_fd, "GET /metrics HTTP/1.1\r\n"
			 "Accept-Encoding: gzip\r\n"
			 "TE: trailers\r\n"
			 "\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(metrics_keep_proxy_and_api_request_totals_separate)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /healthy HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(send_request(peer_fd, "GET /metrics HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "neosocksd_requests_total 13\n"));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "neosocksd_api_requests_total 2\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(metrics_appends_ruleset_metrics_when_defined)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
#if WITH_RULESET
	s.ruleset = (struct ruleset *)&s;
	RS.metrics_ok = true;
#endif
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /metrics HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
#if WITH_RULESET
		T_EXPECT(find_bytes(rsp, (size_t)n, "custom_metric 1\n"));
		T_EXPECT_EQ(RS.metrics_call_count, (size_t)1);
#endif
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_get_ok_with_nocache)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /stats HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n,
			"Content-Type: text/plain; charset=utf-8\r\n"));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Cache-Control: no-store\r\n"));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Server Time"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_output_format_has_no_raw_specifiers)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /stats HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Server Time         : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Uptime              : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Num Sessions        : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Num Rejected        : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Conn Accepts        : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Requests            : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "API Requests        : "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Name Resolves       : "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Traffic             : Up "));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "%ju"));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "%zu"));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "%s"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_post_ok_without_nocache)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /stats HTTP/1.1\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(!find_bytes(
			rsp, (size_t)n, "Cache-Control: no-store\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_bad_method_405)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "PUT /stats HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 405 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_bad_query_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /stats?% HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 400 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_deflate_response_header)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /stats HTTP/1.1\r\n"
			 "Accept-Encoding: deflate\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Content-Encoding: deflate\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(not_found_404)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "GET /notfound HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 404 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

#if WITH_RULESET
T_DECLARE_CASE(stats_post_with_ruleset_q)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.stats_str = "q stats\n";
	RS.stats_len = sizeof("q stats\n") - 1;
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /stats?q=abc HTTP/1.1\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(RS.stats_call_count > 0);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_disabled_returns_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	core.ruleset = NULL;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\n"
			 "Content-Length: 1\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n,
			"ruleset is not enabled on the server"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_invoke_ok_200)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.invoke_ok = true;
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\n"
			 "Content-Length: 1\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_invoke_length_required_411)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "POST /ruleset/invoke HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 411 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_update_ok_contains_time_cost)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.update_ok = true;
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /ruleset/update?module=libruleset&chunkname=%40x.lua HTTP/1.1\r\n"
		"Content-Length: 1\r\n\r\n"
		"x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Time Cost"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_gc_ok_contains_report)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.gc_ok = true;
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(peer_fd, "POST /ruleset/gc HTTP/1.1\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Difference"));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Time Cost"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_rpcall_bad_mime_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: text/plain\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 400 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_rpcall_ok_deflate_response)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[16384];
	int ruleset_tag = 0;
	static char large_result[300];

	T_CHECK(loop != NULL);
	memset(large_result, 'A', sizeof(large_result));
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = false;
	RS.rpcall_result = large_result;
	RS.rpcall_resultlen = sizeof(large_result);
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\n"
			 "Accept-Encoding: deflate\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	T_CHECK(test_wait_until(
		loop, ruleset_rpcall_pending, NULL, TEST_WAIT_RECV_SEC));
	finish_rpcall(loop);
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Content-Type: " MIME_RPCALL "\r\n"));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Content-Encoding: deflate\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_rpcall_sync_fail_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.rpcall_ok = false;
	RS.errstr = "rpcall failed";
	RS.errlen = sizeof("rpcall failed") - 1;
	init_server_pair(&api, &core, loop);
	api.ruleset = (struct ruleset *)&ruleset_tag;
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "rpcall failed"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, healthy_keepalive_reuse_connection);
	T_RUN_CASE(t, healthy_connection_close_header);
	T_RUN_CASE(t, api_stats_do_not_pollute_proxy_stats_in_unified_server);
	T_RUN_CASE(t, metrics_keep_proxy_and_api_request_totals_separate);
	T_RUN_CASE(t, metrics_unsupported_accept_encoding_and_te_returns_200);
	T_RUN_CASE(t, metrics_appends_ruleset_metrics_when_defined);
	T_RUN_CASE(t, stats_get_ok_with_nocache);
	T_RUN_CASE(t, stats_output_format_has_no_raw_specifiers);
	T_RUN_CASE(t, stats_post_ok_without_nocache);
	T_RUN_CASE(t, stats_bad_method_405);
	T_RUN_CASE(t, stats_bad_query_400);
	T_RUN_CASE(t, stats_deflate_response_header);
	T_RUN_CASE(t, not_found_404);

#if WITH_RULESET
	T_RUN_CASE(t, stats_post_with_ruleset_q);
	T_RUN_CASE(t, ruleset_disabled_returns_500);
	T_RUN_CASE(t, ruleset_invoke_ok_200);
	T_RUN_CASE(t, ruleset_invoke_length_required_411);
	T_RUN_CASE(t, ruleset_update_ok_contains_time_cost);
	T_RUN_CASE(t, ruleset_gc_ok_contains_report);
	T_RUN_CASE(t, ruleset_rpcall_bad_mime_400);
	T_RUN_CASE(t, ruleset_rpcall_ok_deflate_response);
	T_RUN_CASE(t, ruleset_rpcall_sync_fail_500);
#endif

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
