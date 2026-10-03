/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for api_server.c; mocked: server, ruleset, resolver. */

#include "api_server.h"

#include "conf.h"
#include "proto/http.h"
#include "resolver.h"
#include "ruleset/ruleset.h"
#include "server.h"

#include "meta/arraysize.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * virtual clock - fire the request timeout (an ev_timer inside a production ctx
 * the test cannot reach) deterministically, with no wall-clock wait. The
 * strong-symbol interposers return a test-advanced virtual time while enabled
 * and pass through to the real clock otherwise, so non-timeout cases are
 * unaffected.
 * ---------------------------------------------------------------------- */

static bool g_vclock_on = false;
static double g_vclock_sec = 0.0;

/* Read the real clock for the pass-through path. Both clock_gettime() and
 * gettimeofday() are interposed here, so the underlying clock has to be reached
 * through a third entry point: ISO C11 timespec_get(), which libc services from
 * its own internal clock rather than through the shadowed symbols. It is also
 * the only such entry point that stays declared under the strict
 * _POSIX_C_SOURCE the FORCE_POSIX build selects. */
static int real_clock(struct timespec *restrict ts)
{
	if (timespec_get(ts, TIME_UTC) != TIME_UTC) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int clock_gettime(clockid_t clk, struct timespec *ts)
{
	if (g_vclock_on) {
		ts->tv_sec = (time_t)g_vclock_sec;
		ts->tv_nsec = (long)((g_vclock_sec - (double)ts->tv_sec) * 1e9);
		return 0;
	}
	(void)clk;
	return real_clock(ts);
}

int gettimeofday(struct timeval *tv, void *tz)
{
	if (g_vclock_on) {
		tv->tv_sec = (time_t)g_vclock_sec;
		tv->tv_usec = (long)((g_vclock_sec - (double)tv->tv_sec) * 1e6);
		return 0;
	}
	(void)tz;
	struct timespec ts;
	if (real_clock(&ts) != 0) {
		return -1;
	}
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = (long)(ts.tv_nsec / 1000);
	return 0;
}

/* Freeze virtual time at the current real instant so a timer armed in real time
 * has a consistent virtual deadline the test crosses by advancing. The case
 * must keep that timeout too large for real elapsed setup time to reach, since
 * the arming happens before the freeze. */
static void vclock_freeze_now(void)
{
	struct timespec ts;
	T_CHECK(real_clock(&ts) == 0);
	g_vclock_sec = (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
	g_vclock_on = true;
}

static void vclock_advance(const double sec)
{
	g_vclock_sec += sec;
}

static void vclock_stop(void)
{
	g_vclock_on = false;
}

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (server, ruleset, resolver) and shared fixtures.
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 1.0,
};

/* Upper bounds on a wait; reaching one is a failure. Both stay below
 * test_conf.timeout so a satisfied wait means the response path acted, not that
 * the request timeout expired. */
static const ev_tstamp TEST_WAIT_CLOSE_SEC = 0.128;
static const ev_tstamp TEST_WAIT_RECV_SEC = 0.128;

/* Bounds an ev_run(EVRUN_ONCE) sleep so a predicate over an fd the loop does
 * not watch is re-checked promptly. */
static const ev_tstamp TEST_TICK_SEC = 0.002;

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

#if WITH_RULESET
/* A string argument a ruleset stub received, copied out of the caller's
 * request buffers, which do not outlive the call. */
struct stub_arg {
	bool present;
	char str[64];
};

static void stub_arg_record(struct stub_arg *restrict a, const char *s)
{
	a->present = (s != NULL);
	a->str[0] = '\0';
	if (s != NULL) {
		(void)snprintf(a->str, sizeof(a->str), "%s", s);
	}
}

static struct {
	bool invoke_ok;
	bool update_ok;
	bool gc_ok;
	bool rpcall_ok;
	bool rpcall_null_result;
	bool rpcall_auto_finish;
	bool rpcall_publish_then_fail;
	bool rpcall_finish_then_fail;
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
	/* the out-pointer ruleset_rpcall wrote *state through (== &ctx->rpcstate);
	 * production state_complete nulls it when the call completes, so the stub
	 * retains it to do the same and stay faithful to the teardown paths */
	struct ruleset_state **rpcstate_out;
	struct ruleset_callback *pending_rpcall;
	size_t cancel_count;
	size_t update_call_count;
	struct stub_arg update_modname;
	struct stub_arg update_chunkname;
	size_t stats_call_count;
	double stats_dt;
	struct stub_arg stats_query;
	bool metrics_ok;
	const char *metrics_str;
	size_t metrics_len;
	size_t metrics_call_count;
	const char *healthy_str;
	size_t healthy_len;
	size_t healthy_call_count;
	struct ev_loop *loop;
} RS = {
	.invoke_ok = true,
	.update_ok = true,
	.gc_ok = true,
	.rpcall_ok = true,
	.rpcall_null_result = false,
	.rpcall_auto_finish = false,
	.rpcall_publish_then_fail = false,
	.rpcall_finish_then_fail = false,
	.stats_ok = true,
	.errstr = "ruleset error",
	.errlen = sizeof("ruleset error") - 1,
	.stats_str = "ruleset stats\n",
	.stats_len = sizeof("ruleset stats\n") - 1,
	.metrics_ok = false,
	.metrics_str = "custom_metric 1\n",
	.metrics_len = sizeof("custom_metric 1\n") - 1,
	.healthy_str = NULL,
	.healthy_len = 0,
	.rpcall_result = "ok",
	.rpcall_resultlen = 2,
	.vmstats_count = 0,
	.vmstats_before = {
		.num_object = 128,
		.byt_allocated = (size_t)1024 * 1024,
		.num_events = 0,
	},
	.vmstats_after = {
		.num_object = 64,
		.byt_allocated = (size_t)512 * 1024,
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
	/* clear a virtual clock a prior timeout case may have left enabled on a
	 * T_EXPECT failure path */
	vclock_stop();
	RS.invoke_ok = true;
	RS.update_ok = true;
	RS.gc_ok = true;
	RS.rpcall_ok = true;
	RS.rpcall_null_result = false;
	RS.rpcall_auto_finish = false;
	RS.rpcall_publish_then_fail = false;
	RS.rpcall_finish_then_fail = false;
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
		.byt_allocated = (size_t)1024 * 1024,
		.num_events = 0,
	};
	RS.vmstats_after = (struct ruleset_vmstats){
		.num_object = 64,
		.byt_allocated = (size_t)512 * 1024,
		.num_events = 0,
	};
	RS.rpcstate = NULL;
	RS.rpcstate_out = NULL;
	RS.pending_rpcall = NULL;
	RS.cancel_count = 0;
	RS.update_call_count = 0;
	RS.update_modname = (struct stub_arg){ .present = false };
	RS.update_chunkname = (struct stub_arg){ .present = false };
	RS.stats_call_count = 0;
	RS.stats_dt = 0.0;
	RS.stats_query = (struct stub_arg){ .present = false };
	RS.metrics_ok = false;
	RS.metrics_str = "custom_metric 1\n";
	RS.metrics_len = sizeof("custom_metric 1\n") - 1;
	RS.metrics_call_count = 0;
	RS.healthy_str = NULL;
	RS.healthy_len = 0;
	RS.healthy_call_count = 0;
	RS.loop = NULL;
}

/* Write the rpcall result into the callback. The real cfunc_rpcall() leaves
 * rpcall.result untouched until completion (rpcall_finish), so this runs only
 * when the call finishes -- never at ruleset_rpcall() return for a pending
 * call -- keeping the stub faithful to the pending-teardown path. */
static void set_rpcall_result(struct ruleset_callback *restrict callback)
{
	if (RS.rpcall_null_result) {
		callback->rpcall.result = NULL;
		callback->rpcall.resultlen = 0;
		return;
	}
	/* rpcall_cb() takes ownership and free()s this */
	char *const copy = malloc(RS.rpcall_resultlen);
	T_CHECK(copy != NULL);
	memcpy(copy, RS.rpcall_result, RS.rpcall_resultlen);
	callback->rpcall.result = copy;
	callback->rpcall.resultlen = RS.rpcall_resultlen;
}

static void finish_rpcall(struct ev_loop *loop)
{
	if (RS.pending_rpcall == NULL) {
		return;
	}
	set_rpcall_result(RS.pending_rpcall);
	/* production state_complete() nulls *selfptr (== ctx->rpcstate) when the
	 * call completes, before rpcall_cb is dispatched; mirror it so teardown
	 * in the completed-but-undispatched window sees rpcstate == NULL */
	if (RS.rpcstate_out != NULL) {
		*RS.rpcstate_out = NULL;
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

bool ruleset_invoke(struct ruleset *restrict r, struct io_stream *code)
{
	(void)r;
	(void)code;
	return RS.invoke_ok;
}

bool ruleset_update(
	struct ruleset *restrict r, const char *restrict modname,
	const char *restrict chunkname, struct io_stream *code)
{
	(void)r;
	(void)code;
	RS.update_call_count++;
	stub_arg_record(&RS.update_modname, modname);
	stub_arg_record(&RS.update_chunkname, chunkname);
	return RS.update_ok;
}

bool ruleset_gc(struct ruleset *restrict r)
{
	(void)r;
	return RS.gc_ok;
}

bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct io_stream *code, struct ruleset_callback *callback)
{
	(void)r;
	(void)code;
	if (!RS.rpcall_ok) {
		if (RS.rpcall_finish_then_fail) {
			/* rpcall_finish() completes the call -- result delivered,
			 * *state nulled and w_finish fed -- and only a later step
			 * raises, so the failure is reported over a call that has
			 * already run */
			RS.rpcstate =
				(struct ruleset_state *)&ruleset_state_tag;
			*state = RS.rpcstate;
			RS.rpcstate_out = state;
			set_rpcall_result(callback);
			*RS.rpcstate_out = NULL;
			ev_feed_event(RS.loop, &callback->w_finish, EV_CUSTOM);
			return false;
		}
		if (RS.rpcall_publish_then_fail) {
			/* cfunc_rpcall publishes *pstate before its last fallible
			 * step, so a failure can leave the state orphaned; emulate
			 * that so the consumer's cancel-on-failure path is tested */
			RS.rpcstate =
				(struct ruleset_state *)&ruleset_state_tag;
			*state = RS.rpcstate;
			RS.rpcstate_out = state;
		}
		return false;
	}
	RS.rpcstate = (struct ruleset_state *)&ruleset_state_tag;
	*state = RS.rpcstate;
	RS.rpcstate_out = state;
	if (RS.rpcall_auto_finish && RS.loop != NULL) {
		/* completes immediately: set the result and null *state before
		 * firing w_finish, as rpcall_finish()/state_complete() would */
		set_rpcall_result(callback);
		*RS.rpcstate_out = NULL;
		ev_feed_event(RS.loop, &callback->w_finish, EV_CUSTOM);
		return true;
	}
	/* pending: leave callback->rpcall.result untouched until finish_rpcall */
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
	RS.stats_call_count++;
	RS.stats_dt = dt;
	stub_arg_record(&RS.stats_query, query);
	if (!RS.stats_ok) {
		/* like the real one, a failure leaves *len unset: the error text
		 * and its length come from ruleset_geterror() */
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

const char *ruleset_healthy(struct ruleset *restrict r, size_t *len)
{
	(void)r;
	RS.healthy_call_count++;
	if (RS.healthy_str == NULL) {
		return NULL;
	}
	if (len != NULL) {
		*len = RS.healthy_len;
	}
	return RS.healthy_str;
}
#endif /* WITH_RULESET */

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

static bool parse_content_length(
	const unsigned char *restrict rsp, const size_t n,
	size_t *restrict out_value)
{
	static const char key[] = "Content-Length: ";
	const size_t keylen = sizeof(key) - 1;
	for (size_t i = 0; i + keylen <= n; i++) {
		if (memcmp(rsp + i, key, keylen) != 0) {
			continue;
		}
		size_t pos = i + keylen;
		size_t value = 0;
		bool has_digit = false;
		while (pos < n && '0' <= rsp[pos] && rsp[pos] <= '9') {
			value = value * 10 + (size_t)(rsp[pos] - '0');
			has_digit = true;
			pos++;
		}
		if (!has_digit) {
			return false;
		}
		*out_value = value;
		return true;
	}
	return false;
}

static bool find_body_offset(
	const unsigned char *restrict rsp, const size_t n,
	size_t *restrict out_offset)
{
	static const char sep[] = "\r\n\r\n";
	const size_t seplen = sizeof(sep) - 1;
	for (size_t i = 0; i + seplen <= n; i++) {
		if (memcmp(rsp + i, sep, seplen) == 0) {
			*out_offset = i + seplen;
			return true;
		}
	}
	return false;
}

/* Receive a complete HTTP response: the header block plus its declared
 * Content-Length body (api_server always frames responses with Content-Length).
 * Waiting is event-driven -- ev_run(EVRUN_ONCE) advances the in-loop server and
 * blocks until more output or the watchdog -- rather than polling a fixed quiet
 * window, so completion tracks the message structure, not a magic tick count. */
static ssize_t recv_all_with_timeout(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	size_t off = 0;
	size_t need = 0; /* total bytes for a complete message, once known */
	bool need_known = false;

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
				ev_run(loop, EVRUN_ONCE);
				continue;
			}
			ev_timer_stop(loop, &w_timeout);
			return -1;
		}
		if (n == 0) {
			break; /* EOF */
		}
		off += (size_t)n;
		if (!need_known) {
			size_t body_off, clen;
			if (find_body_offset(buf, off, &body_off) &&
			    parse_content_length(buf, body_off, &clen)) {
				need = body_off + clen;
				need_known = true;
			}
		}
		if (need_known && off >= need) {
			break;
		}
	}
	ev_timer_stop(loop, &w_timeout);
	return (ssize_t)off;
}

static void
test_tick_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	/* No-op: this timer exists only to bound ev_run(EVRUN_ONCE) sleeps. */
	(void)loop;
	(void)w;
	(void)revents;
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static bool ruleset_rpcall_pending(void *data)
{
	(void)data;
	return RS.pending_rpcall != NULL;
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
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_cloexec(sv[0]) == 0);
	T_CHECK(socket_set_nonblock(sv[0]) == 0);
	T_CHECK(socket_set_cloexec(sv[1]) == 0);
	T_CHECK(socket_set_nonblock(sv[1]) == 0);
	api_serve(api, loop, sv[0], (const struct sockaddr *)&sa);
	*peer_fd = sv[1];
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

static bool send_request(const int peer_fd, const char *restrict req)
{
	return write_all(peer_fd, req, strlen(req)) == 0;
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

/* Offset of the first occurrence of needle in haystack, or haystack_len when
 * absent (so a "found before" comparison fails safely). */
static size_t find_bytes_offset(
	const unsigned char *restrict haystack, const size_t haystack_len,
	const char *restrict needle)
{
	const size_t needle_len = strlen(needle);
	if (needle_len == 0 || haystack_len < needle_len) {
		return haystack_len;
	}
	for (size_t i = 0; i + needle_len <= haystack_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0) {
			return i;
		}
	}
	return haystack_len;
}

/* Number of non-overlapping occurrences of needle in haystack. */
static size_t count_bytes(
	const unsigned char *restrict haystack, const size_t haystack_len,
	const char *restrict needle)
{
	const size_t needle_len = strlen(needle);
	if (needle_len == 0 || haystack_len < needle_len) {
		return 0;
	}
	size_t count = 0;
	for (size_t i = 0; i + needle_len <= haystack_len;) {
		if (memcmp(haystack + i, needle, needle_len) != 0) {
			i++;
			continue;
		}
		count++;
		i += needle_len;
	}
	return count;
}

/* Copy the value text of one Prometheus sample. `name` carries the leading
 * newline so it matches the sample line, not the HELP/TYPE lines above it. */
static bool read_metric_text(
	const unsigned char *restrict rsp, const size_t n,
	const char *restrict name, char *restrict buf, const size_t bufsize)
{
	const size_t off = find_bytes_offset(rsp, n, name);
	if (off >= n) {
		return false;
	}
	size_t len = 0;
	for (size_t i = off + strlen(name); i < n && rsp[i] != '\n'; i++) {
		if (len + 1 >= bufsize) {
			return false;
		}
		buf[len++] = (char)rsp[i];
	}
	buf[len] = '\0';
	return true;
}

/* Read back the value of one Prometheus sample. */
static bool parse_metric_value(
	const unsigned char *restrict rsp, const size_t n,
	const char *restrict name, double *restrict out)
{
	char buf[64];
	if (!read_metric_text(rsp, n, name, buf, sizeof(buf))) {
		return false;
	}
	char *end = NULL;
	*out = strtod(buf, &end);
	return end != buf;
}

static bool assert_status(
	const unsigned char *restrict rsp, const size_t n, const char *code)
{
	return find_bytes(rsp, n, code);
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - REST/RPC endpoints, keepalive and error responses.
 * ---------------------------------------------------------------------- */

/* Host validation must finish before endpoint dispatch or body handling. */
T_DECLARE_CASE(host_validation_before_api_dispatch)
{
	static const struct {
		const char *headers;
		const char *version;
		const char *status;
	} cases[] = {
		{ "", "HTTP/1.1", " 400 " },
		{ "Host: test\r\nhOsT: test\r\n", "HTTP/1.1", " 400 " },
		{ "Host: user@test\r\n", "HTTP/1.1", " 400 " },
		{ "Host: bad host\r\n", "HTTP/1.1", " 400 " },
		{ "Host: [broken]\r\n", "HTTP/1.1", " 400 " },
		{ "Host: test:abc\r\n", "HTTP/1.1", " 400 " },
		{ "", "HTTP/1.0", " 200 " },
		{ "Host: test\r\nHost: other\r\n", "HTTP/1.0", " 400 " },
		{ "Host: test/path\r\n", "HTTP/1.0", " 400 " },
		{ "Host: [::1]:80\r\n", "HTTP/1.1", " 200 " },
		{ "Host:\r\n", "HTTP/1.1", " 200 " },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct ev_loop *loop = ev_loop_new(0);
		struct server api, core;
		int peer_fd = -1;
		char req[256];
		unsigned char rsp[4096];
		T_CHECK(loop != NULL);
		init_server_pair(&api, &core, loop);
		start_api(&api, loop, &peer_fd);
		const int n = snprintf(
			req, sizeof(req),
			"GET /healthy %s\r\n%sConnection: close\r\n\r\n",
			cases[i].version, cases[i].headers);
		T_CHECK(n > 0 && (size_t)n < sizeof(req));
		T_CHECK(send_request(peer_fd, req));
		const ssize_t received = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		const bool ok =
			received > 0 &&
			assert_status(rsp, (size_t)received, cases[i].status);
		const uintmax_t dispatched = api.stats.num_api_request;
		T_CHECK(close(peer_fd) == 0);
		ev_loop_destroy(loop);
		T_EXPECT(ok);
		T_EXPECT_EQ(
			dispatched,
			strcmp(cases[i].status, " 200 ") == 0 ? 1 : 0);
	}
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

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Connection: keep-alive\r\n"));
	}

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Collect responses until `want` status lines have arrived or the reads stop
 * producing; returns how many were seen. Bounded by `want` reads, each with its
 * own timeout, so a missing response fails the assertion instead of hanging. */
static size_t recv_responses(
	struct ev_loop *loop, const int peer_fd, unsigned char *restrict buf,
	const size_t cap, const size_t want)
{
	size_t total = 0;
	for (size_t i = 0; i < want; i++) {
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, buf + total, cap - total,
			TEST_WAIT_RECV_SEC);
		if (n <= 0) {
			break;
		}
		total += (size_t)n;
		if (count_bytes(buf, total, "HTTP/1.1 200") >= want) {
			break;
		}
	}
	return count_bytes(buf, total, "HTTP/1.1 200");
}

/*
 * Regression: two requests delivered in one segment. The keep-alive reset used
 * to re-init the parser over a zeroed rbuf, discarding the second request --
 * which the socket had already handed over, so nothing would ever report it
 * readable again and the connection sat idle until the timeout.
 */
T_DECLARE_CASE(pipelined_requests_both_answered)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"
			 "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	T_EXPECT_EQ(recv_responses(loop, peer_fd, rsp, sizeof(rsp), 2), 2);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * The same carry-over, but where the first request has a Content-Length body:
 * the consumed mark must cover the body bytes taken out of rbuf, or the leftover
 * would start inside the body and parse as garbage.
 */
T_DECLARE_CASE(pipelined_after_body_request_both_answered)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /stats?nobanner=1 HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 4\r\n\r\n"
			 "body"
			 "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	T_EXPECT_EQ(recv_responses(loop, peer_fd, rsp, sizeof(rsp), 2), 2);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: an endpoint that reads no request body must drop it, or
 * http_conn_send writes those bytes out behind the response header. /healthy
 * answers Content-Length: 0, so a trailing byte is read by the client as the
 * start of the next response and desyncs the keep-alive stream.
 */
T_DECLARE_CASE(healthy_request_body_is_not_echoed)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 19\r\n\r\n"
			 "HTTP/1.1 500 PWNED\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		size_t body_off = 0;
		T_CHECK(find_body_offset(rsp, (size_t)n, &body_off));
		/* Content-Length: 0 makes the header block the whole response */
		T_EXPECT_EQ((size_t)n, body_off);
	}

	/* the stream is still in sync: the next read starts at a status line */
	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT_EQ(
			find_bytes_offset(rsp, (size_t)n, "HTTP/1.1 200"),
			(size_t)0);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

struct fd_closed_ctx {
	int fd;
};

/* True once the peer end reports EOF, i.e. the server closed its side. A byte
 * still queued reads as "not closed yet" and is consumed. */
static bool fd_closed_predicate(void *data)
{
	struct fd_closed_ctx *const ctx = data;
	for (;;) {
		unsigned char ch;
		const ssize_t n = recv(ctx->fd, &ch, sizeof(ch), MSG_DONTWAIT);
		if (n >= 0) {
			return n == 0;
		}
		const int err = errno;
		if (err != EINTR) {
			return false;
		}
	}
}

/*
 * Regression: a `Connection: close` request must actually tear the connection
 * down. Waiting for the peer's EOF terminates on that event and fails on the
 * timeout, where accepting "closed or nothing to read" passed either way.
 */
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
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n"
			 "Connection: close\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Connection: close\r\n"));
	}

	{
		struct fd_closed_ctx closed = { .fd = peer_fd };
		T_EXPECT(test_wait_until(
			loop, fd_closed_predicate, &closed,
			TEST_WAIT_CLOSE_SEC));
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

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
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
		peer_fd, "GET /metrics HTTP/1.1\r\nHost: test\r\n"
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

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(send_request(
		peer_fd, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "neosocksd_requests_total 13\n"));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "neosocksd_api_requests_total 2\n"));
#if WITH_RULESET
		/* every protocol_bytes_total sample stays in one contiguous
		 * group: the api_client rows must precede the following
		 * api_client_requests_total family (Prometheus text-format rule) */
		const size_t off_api_client_bytes = find_bytes_offset(
			rsp, (size_t)n,
			"neosocksd_protocol_bytes_total{direction=\"tx\",module=\"api_client\"}");
		const size_t off_requests_family = find_bytes_offset(
			rsp, (size_t)n,
			"# TYPE neosocksd_api_client_requests_total");
		T_EXPECT(off_api_client_bytes < (size_t)n);
		T_EXPECT(off_requests_family < (size_t)n);
		T_EXPECT(off_api_client_bytes < off_requests_family);
#endif /* WITH_RULESET */
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
	reset_ruleset_stub();
	s.ruleset = (struct ruleset *)&s;
	RS.metrics_ok = true;
#endif
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n"));
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

/*
 * Regression: a Prometheus float sample must carry the whole value. "%g" prints
 * 6 significant digits, which cannot resolve a second of a long uptime, so a
 * counter consumed by rate() sat still between scrapes and then jumped.
 */
T_DECLARE_CASE(metrics_float_sample_keeps_full_precision)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[8192];
	/* about 39 years, far enough out that 6 significant digits quantize it
	 * to a multiple of 10 ks */
	static const int_least64_t uptime_ns = 1234567890123456789;

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
	s.stats.started = (int_least64_t)clock_monotonic_ns() - uptime_ns;
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		const double expect =
			(double)((int_least64_t)clock_monotonic_ns() -
				 s.stats.started) *
			1e-9;
		double uptime = 0.0;
		T_CHECK(parse_metric_value(
			rsp, (size_t)n, "\nneosocksd_uptime_seconds ",
			&uptime));
		T_EXPECT(fabs(uptime - expect) < 1.0);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Switch LC_NUMERIC to the first installed locale that spells the decimal point
 * with something other than '.'; NULL when the host has none, LC_NUMERIC then
 * left in the C locale. */
static const char *set_comma_locale(void)
{
	static const char *const names[] = {
		"de_DE.UTF-8", "de_DE.utf8",  "de_DE",	     "de_DE@euro",
		"fr_FR.UTF-8", "fr_FR.utf8",  "fr_FR",	     "es_ES.UTF-8",
		"it_IT.UTF-8", "nl_NL.UTF-8", "pt_BR.UTF-8", "ru_RU.UTF-8",
	};
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		if (setlocale(LC_NUMERIC, names[i]) == NULL) {
			continue;
		}
		if (localeconv()->decimal_point[0] != '.') {
			return names[i];
		}
	}
	(void)setlocale(LC_NUMERIC, "C");
	return NULL;
}

/*
 * Regression: the exposition format wants a '.' decimal separator, but printf
 * writes the one LC_NUMERIC names, so a host running with a comma locale served
 * "neosocksd_uptime_seconds 3,01134" and failed the whole scrape.
 */
T_DECLARE_CASE(metrics_float_sample_ignores_lc_numeric)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[8192];
	char value[64];
	/* far enough out that the shortest round-trip form carries fractional
	 * digits, so the sample really contains a decimal separator */
	static const int_least64_t uptime_ns = 1234567890123456789;

	T_CHECK(loop != NULL);
	const char *const numeric = set_comma_locale();
	if (numeric == NULL) {
		ev_loop_destroy(loop);
		T_LOG("no installed locale uses a non-'.' decimal point");
		T_SKIPNOW();
	}
	T_LOGF("LC_NUMERIC=%s decimal_point=\"%s\"", numeric,
	       localeconv()->decimal_point);

	init_unified_server(&s, loop);
	s.stats.started = (int_least64_t)clock_monotonic_ns() - uptime_ns;
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n"));
	const ssize_t n = recv_all_with_timeout(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
	const bool ok =
		n > 0 && read_metric_text(
				 rsp, (size_t)n, "\nneosocksd_uptime_seconds ",
				 value, sizeof(value));
	/* restore before the first assertion: a failing one aborts the case */
	(void)setlocale(LC_NUMERIC, "C");

	T_EXPECT(ok);
	T_LOGF("uptime sample: \"%s\"", value);
	T_EXPECT(strchr(value, '.') != NULL);
	/* Go ParseFloat accepts nothing outside this set */
	T_EXPECT(value[strspn(value, "0123456789.eE+-")] == '\0');
	T_EXPECT(strtod(value, NULL) > 1.0e9);

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

	T_CHECK(send_request(
		peer_fd, "GET /stats HTTP/1.1\r\nHost: test\r\n\r\n"));
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

	T_CHECK(send_request(
		peer_fd, "GET /stats HTTP/1.1\r\nHost: test\r\n\r\n"));
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
			rsp, (size_t)n, "Upstream Setup      : Rx "));
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
		peer_fd,
		"POST /stats HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"));
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

/*
 * Regression: the rate window is a single window. A POST that omits the server
 * statistics still closes it, so the counter baselines have to move with the
 * timestamp; leaving them behind divided the whole backlog by the next
 * request's short dt and reported a burst that never happened.
 */
T_DECLARE_CASE(stats_post_without_server_advances_rate_baselines)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	/* the window statics outlive each case, so this request only takes this
	 * case's own baselines */
	T_CHECK(send_request(
		peer_fd, "POST /stats?nobanner=1 HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	/* traffic that belongs to the window the next request closes */
	core.listeners[0].stats.num_accept += 100;
	core.listeners[0].stats.num_serve += 100;
	T_CHECK(send_request(
		peer_fd,
		"POST /stats?nobanner=1&server=0 HTTP/1.1\r\nHost: test\r\n"
		"Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "Accept Rate"));
	}

	/* no counter moved since, so every rate over this window is zero */
	T_CHECK(send_request(
		peer_fd, "POST /stats?nobanner=1 HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n,
			"Accept Rate         : 0.0/s (+0.0/s)\n"));
		T_EXPECT(find_bytes(
			rsp, (size_t)n,
			"Reject Rate         : ruleset=0.0/s, timeout=0.0/s, upstream=0.0/s\n"));
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

	T_CHECK(send_request(
		peer_fd, "PUT /stats HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 405 "));
		/* RFC 9110 §10.2.1: a 405 must carry Allow */
		T_EXPECT(find_bytes(rsp, (size_t)n, "Allow: GET, POST\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* /metrics rejects a non-GET method with 405 + Allow (http_handle_metrics). */
T_DECLARE_CASE(metrics_bad_method_405)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_unified_server(&s, loop);
	start_api(&s, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "PUT /metrics HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 405 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Allow: GET\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* /healthy is read-only: a non-GET method is 405 + Allow (restapi_check). */
T_DECLARE_CASE(healthy_bad_method_405)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /healthy HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 405 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Allow: GET\r\n"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A trailing path segment on a leaf endpoint is 404 (restapi_check). */
T_DECLARE_CASE(stats_trailing_path_404)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /stats/extra HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 404 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(chunked_request_rejected_501)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	/* http_conn frames only Content-Length bodies, so a chunked request body
	 * is left unconsumed in rbuf and discarded on the keep-alive reset,
	 * desyncing the stream. restapi_check must reject chunked with 501 and
	 * close the connection rather than dispatch a no-body endpoint over it.
	 * /stats is a require_content=false endpoint, the path the bug affected. */
	T_CHECK(send_request(
		peer_fd, "GET /stats HTTP/1.1\r\nHost: test\r\n"
			 "Transfer-Encoding: chunked\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 501 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Connection: close\r\n"));
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

	T_CHECK(send_request(
		peer_fd, "GET /stats?% HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 400 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_key_only_query_options)
{
	static const char *const requests[] = {
		"GET /stats?nobanner HTTP/1.1\r\nHost: test\r\n\r\n",
		"GET /stats?server HTTP/1.1\r\nHost: test\r\n\r\n",
		"GET /stats?runtime HTTP/1.1\r\nHost: test\r\n\r\n",
		"GET /stats?nobanner&server&runtime HTTP/1.1\r\nHost: test\r\n\r\n",
	};
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		struct ev_loop *loop = ev_loop_new(0);
		struct server api, core;
		int peer_fd = -1;
		unsigned char rsp[8192];

		T_CHECK(loop != NULL);
		init_server_pair(&api, &core, loop);
		start_api(&api, loop, &peer_fd);

		/* A key-only query component has a NULL value; it must be
		 * treated as false rather than dereferenced. */
		T_CHECK(send_request(peer_fd, requests[i]));
		{
			const ssize_t n = recv_all_with_timeout(
				loop, peer_fd, rsp, sizeof(rsp),
				TEST_WAIT_RECV_SEC);
			T_EXPECT(n > 0);
			T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
			/* nobanner stayed false, so the banner is still there */
			T_EXPECT(find_bytes(rsp, (size_t)n, "neosocksd "));
		}

		T_CHECK(close(peer_fd) == 0);
		ev_loop_destroy(loop);
	}
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
		peer_fd, "GET /stats HTTP/1.1\r\nHost: test\r\n"
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

	T_CHECK(send_request(
		peer_fd, "GET /notfound HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 404 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* api_handle()'s url_parse() failure path: invalid percent-encoding in the
 * authority makes url_parse reject the request target -> 400. */
T_DECLARE_CASE(malformed_url_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET http://%zz/ HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 400 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_connect_latency_shows_percentiles)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	core.stats.num_connects = 3;
	core.stats.connect_ns[0] = 100000000; /* 100 ms */
	core.stats.connect_ns[1] = 200000000; /* 200 ms */
	core.stats.connect_ns[2] = 300000000; /* 300 ms */
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /stats HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Connect Latency"));
		T_EXPECT(find_bytes(rsp, (size_t)n, "P50="));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(stats_nobanner_option_suppresses_banner)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];

	T_CHECK(loop != NULL);
	init_server_pair(&api, &core, loop);
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"GET /stats?nobanner=1 HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Server Time"));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "neosocksd "));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /stats?q=a%20b HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT_EQ(RS.stats_call_count, (size_t)1);
		/* the ruleset stats output must actually reach the body, not just
		 * be requested */
		T_EXPECT(find_bytes(rsp, (size_t)n, "q stats"));
	}
	/* the filter reaches ruleset.stats percent-decoded */
	T_EXPECT(RS.stats_query.present);
	T_EXPECT_STREQ(RS.stats_query.str, "a b");

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* ruleset.stats gets the same window the server rates are taken over: the time
 * since the previous stateful request, in seconds; with no q it gets no filter. */
T_DECLARE_CASE(stats_post_ruleset_dt_is_rate_window)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	/* the window is measured on the virtual clock from here on; the advance
	 * below stays short of test_conf.timeout, armed on real time before the
	 * freeze, so the connection outlives it. The window statics outlive each
	 * case, so the first request only opens this case's window. */
	vclock_freeze_now();
	T_CHECK(send_request(
		peer_fd,
		"POST /stats HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT_EQ(RS.stats_call_count, (size_t)1);
	}

	vclock_advance(0.5);
	/* re-read the clock, or the next wait's watchdog is armed against the
	 * loop's cached pre-advance time and expires on its first run */
	ev_now_update(loop);
	T_CHECK(send_request(
		peer_fd,
		"POST /stats HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT_EQ(RS.stats_call_count, (size_t)2);
	}
	T_EXPECT(fabs(RS.stats_dt - 0.5) < 1e-3);
	T_EXPECT(!RS.stats_query.present);
	vclock_stop();

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A failing ruleset.stats does not fail the request: its error text takes the
 * place of the ruleset section in the 200 body. */
T_DECLARE_CASE(stats_post_ruleset_error_in_body)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[8192];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.stats_ok = false;
	RS.errstr = "stats failed";
	RS.errlen = sizeof("stats failed") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /stats?nobanner=1&server=0 HTTP/1.1\r\nHost: test\r\n"
		"Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT_EQ(RS.stats_call_count, (size_t)1);

		size_t body_off = 0;
		T_CHECK(find_body_offset(rsp, (size_t)n, &body_off));
		T_EXPECT_EQ((size_t)n - body_off, RS.errlen);
		T_EXPECT(find_bytes(rsp, (size_t)n, "stats failed"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(healthy_unhealthy_returns_503)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.healthy_str = "db down";
	RS.healthy_len = sizeof("db down") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 503 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "db down"));
		T_EXPECT(RS.healthy_call_count > 0);
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
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\nHost: test\r\n"
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

/* process_cb()'s fallback 404 for an unrecognized /ruleset/<action>. */
T_DECLARE_CASE(ruleset_unknown_action_404)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/bogus HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 404 "));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\nHost: test\r\n"
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

T_DECLARE_CASE(ruleset_invoke_empty_body_ok_200)
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	/* Regression: Content-Length: 0 leaves conn.cbuf unallocated (NULL);
	 * this must not crash the server. */
	T_CHECK(send_request(
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: send_errmsg declared the full, unclamped error length in
 * Content-Length while BUF_APPEND silently truncated the body to whatever
 * room remained in the fixed-size wbuf (e.g. a Lua traceback exceeding
 * ~8KB). A keep-alive-tolerant client relying on Content-Length (rather
 * than EOF) to know when the response ends would read a truncated body.
 */
static void reset_warning_log(void *data)
{
	(void)data;
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
}

static void count_warning(void *data, const unsigned char *buf, size_t len)
{
	(void)buf;
	(void)len;
	(*(size_t *)data)++;
}

T_DECLARE_CASE(errmsg_content_length_matches_truncated_body)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	int ruleset_tag = 0;
	static unsigned char rsp[16384];
	/* ruleset_geterror() returns a NUL-terminated Lua string. */
	static char big_err[10001];

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	for (size_t i = 0; i < sizeof(big_err) - 1; i++) {
		big_err[i] = (char)('a' + (i % 26));
	}
	big_err[sizeof(big_err) - 1] = '\0';
	size_t warnings = 0;
	T_CLEANUP(reset_warning_log, NULL);
	slog_setoutput(SLOG_OUTPUT_WRITER, count_warning, &warnings);
	slog_setlevel(LOG_LEVEL_WARNING);
	RS.invoke_ok = false;
	RS.errstr = big_err;
	RS.errlen = sizeof(big_err) - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/invoke HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));

		size_t declared_len = 0;
		T_CHECK(parse_content_length(rsp, (size_t)n, &declared_len));
		size_t body_off = 0;
		T_CHECK(find_body_offset(rsp, (size_t)n, &body_off));
		const size_t actual_body_len = (size_t)n - body_off;

		/* confirm the message was actually too large to fit whole,
		 * and that Content-Length always matches what was sent */
		T_EXPECT(declared_len < sizeof(big_err) - 1);
		T_EXPECT_EQ(actual_body_len, declared_len);
	}

	reset_warning_log(NULL);
	T_EXPECT_EQ(warnings, 1);
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /ruleset/invoke HTTP/1.1\r\nHost: test\r\n\r\n"));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /ruleset/update?module=libruleset&chunkname=%40x.lua HTTP/1.1\r\nHost: test\r\n"
		"Content-Length: 1\r\n\r\n"
		"x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "Time Cost"));
	}
	/* each query value reaches its own parameter, percent-decoded */
	T_EXPECT_EQ(RS.update_call_count, (size_t)1);
	T_EXPECT(RS.update_modname.present);
	T_EXPECT_STREQ(RS.update_modname.str, "libruleset");
	T_EXPECT(RS.update_chunkname.present);
	T_EXPECT_STREQ(RS.update_chunkname.str, "@x.lua");

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A failed update answers 500 with the ruleset's error text; with no query the
 * ruleset is asked to update the main ruleset with no chunk name (both NULL). */
T_DECLARE_CASE(ruleset_update_fail_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.update_ok = false;
	RS.errstr = "update failed";
	RS.errlen = sizeof("update failed") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/update HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "update failed"));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "Time Cost"));
	}
	T_EXPECT_EQ(RS.update_call_count, (size_t)1);
	T_EXPECT(!RS.update_modname.present);
	T_EXPECT(!RS.update_chunkname.present);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A malformed /ruleset/update query is refused before the ruleset runs. */
T_DECLARE_CASE(ruleset_update_bad_query_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd,
		"POST /ruleset/update?module=m&% HTTP/1.1\r\nHost: test\r\n"
		"Content-Length: 1\r\n\r\n"
		"x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 400 "));
	}
	T_EXPECT_EQ(RS.update_call_count, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_update_empty_body_ok_200)
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	/* Regression: Content-Length: 0 leaves conn.cbuf unallocated (NULL);
	 * this must not crash the server. */
	T_CHECK(send_request(
		peer_fd,
		"POST /ruleset/update?module=libruleset&chunkname=%40x.lua HTTP/1.1\r\nHost: test\r\n"
		"Content-Length: 0\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_removed_before_processing)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[2048];
	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	init_server_pair(&api, &core, loop);
	core.ruleset = (struct ruleset *)&test_conf;
	start_api(&api, loop, &peer_fd);
	T_CHECK(send_request(
		peer_fd, "POST /ruleset/gc HTTP/1.1\r\nHost: test\r\n"
			 "Connection: close\r\n\r\n"));
	ev_run(loop, EVRUN_NOWAIT);
	T_CHECK(api.stats.num_api_request == 1);
	core.ruleset = NULL;
	const ssize_t n = recv_all_with_timeout(
		loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
	T_EXPECT(n > 0);
	T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
	T_EXPECT(find_bytes(
		rsp, (size_t)n, "ruleset is not enabled on the server"));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/gc HTTP/1.1\r\nHost: test\r\n\r\n"));
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

/* A failed collection answers 500 with the ruleset's error text instead of the
 * report. */
T_DECLARE_CASE(ruleset_gc_fail_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.gc_ok = false;
	RS.errstr = "gc failed";
	RS.errlen = sizeof("gc failed") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/gc HTTP/1.1\r\nHost: test\r\n\r\n"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "gc failed"));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "Difference"));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
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

/*
 * Regression: connection teardown while an rpcall is still pending (its
 * finish event never fed) must not crash or leak the buffered result --
 * api_ctx_stop() must clear ctx->rpcreturn.rpcall.result itself, since
 * rpcall_cb() will now never run to free it.
 */
static bool ruleset_cancelled_once(void *data)
{
	(void)data;
	return RS.cancel_count >= 1;
}

T_DECLARE_CASE(ruleset_rpcall_pending_torn_down_by_timeout)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = false;
	/* the rpcall must reach the pending state on real time first, so the
	 * request deadline is armed before the freeze below: keep it far out of
	 * real elapsed reach, or slow setup fires the timer on its own and the
	 * cancel this case asserts is no longer the one the advance caused */
	test_conf.timeout = 10.0;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	T_CHECK(test_wait_until(
		loop, ruleset_rpcall_pending, NULL, TEST_WAIT_RECV_SEC));

	/* Cross the request-timeout deadline on the virtual clock while the rpcall
	 * is still pending; the next ev_run fires the timer and cancels it -- no
	 * wall-clock wait. */
	vclock_freeze_now();
	vclock_advance(test_conf.timeout + 1.0);
	T_EXPECT(test_wait_until(
		loop, ruleset_cancelled_once, NULL, TEST_WAIT_RECV_SEC));
	T_EXPECT_EQ(RS.cancel_count, (size_t)1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
	test_conf.timeout = 1.0;
}

/*
 * A ruleset rpcall that completes before ruleset_rpcall() returns -- result set
 * and *state nulled inside the call, w_finish already fed -- must answer
 * normally, with rpcall_cb dispatched on a ctx whose rpcstate is already NULL.
 */
T_DECLARE_CASE(ruleset_rpcall_sync_finish_ok_200)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = true;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
		T_EXPECT(find_bytes(
			rsp, (size_t)n, "Content-Type: " MIME_RPCALL "\r\n"));
	}
	/* it finished inside the call: nothing was left pending or cancelled */
	T_EXPECT(RS.pending_rpcall == NULL);
	T_EXPECT_EQ(RS.cancel_count, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Complete the pending rpcall from inside the loop's dispatch, so the finish
 * event is queued while the request timeout is already pending. */
static void
finish_rpcall_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	(void)w;
	(void)revents;
	finish_rpcall(loop);
}

/*
 * Regression: teardown in the completed-but-undispatched window -- the result
 * delivered, ctx->rpcstate already NULL and w_finish still pending.
 * api_ctx_stop() has to clear the pending event and free the result there too;
 * skipping it leaves a queued event on the freed ctx (dispatched onto freed
 * memory) and leaks the result rpcall_cb() will never consume.
 */
T_DECLARE_CASE(ruleset_rpcall_finished_torn_down_before_dispatch)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	int ruleset_tag = 0;
	struct ev_timer w_finish_race;
	struct fd_closed_ctx closed_ctx = { 0 };

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = false;
	/* both deadlines below must stay out of real elapsed reach until the
	 * advance crosses them, or slow setup fires one on its own */
	test_conf.timeout = 10.0;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	T_CHECK(test_wait_until(
		loop, ruleset_rpcall_pending, NULL, TEST_WAIT_RECV_SEC));

	/* Open the window inside one dispatch batch: the earlier deadline runs
	 * first, so the call completes before the request timeout tears the ctx
	 * down, and w_finish is demoted to the lowest priority so the event it
	 * feeds cannot overtake the timeout already queued at the default one. */
	ev_set_priority(&RS.pending_rpcall->w_finish, EV_MINPRI);
	ev_timer_init(
		&w_finish_race, finish_rpcall_cb, test_conf.timeout * 0.5, 0.0);
	ev_timer_start(loop, &w_finish_race);
	vclock_freeze_now();
	vclock_advance(test_conf.timeout + 1.0);
	ev_run(loop, EVRUN_ONCE);
	ev_timer_stop(loop, &w_finish_race);

	/* the teardown saw a completed call: no cancel, and no response -- the
	 * ctx was destroyed before rpcall_cb could run */
	T_EXPECT(RS.pending_rpcall == NULL);
	T_EXPECT_EQ(RS.cancel_count, (size_t)0);
	closed_ctx.fd = peer_fd;
	T_EXPECT(fd_closed_predicate(&closed_ctx));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
	test_conf.timeout = 1.0;
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
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

T_DECLARE_CASE(ruleset_rpcall_empty_body_ok)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = false;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	/* Regression: Content-Length: 0 leaves conn.cbuf unallocated (NULL);
	 * this must not crash the server. */
	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 0\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"));
	T_CHECK(test_wait_until(
		loop, ruleset_rpcall_pending, NULL, TEST_WAIT_RECV_SEC));
	finish_rpcall(loop);
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 200 "));
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
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
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

/*
 * A completed rpcall that returns no result must yield 500 "rpcall did not
 * return" -- rpcall_cb's result == NULL branch.
 */
T_DECLARE_CASE(ruleset_rpcall_null_result_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = true;
	RS.rpcall_auto_finish = false;
	RS.rpcall_null_result = true;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
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
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "rpcall did not return"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * ruleset_rpcall can fail after already publishing *pstate (== ctx->rpcstate),
 * orphaning a state whose cb still targets this ctx. The failure path must
 * cancel it so a later Lua GC cannot feed w_finish on the freed/reused ctx.
 */
T_DECLARE_CASE(ruleset_rpcall_orphaned_state_cancelled)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.rpcall_ok = false;
	RS.rpcall_publish_then_fail = true;
	RS.errstr = "rpcall failed";
	RS.errlen = sizeof("rpcall failed") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
	}
	/* the orphaned state was cancelled exactly once */
	T_EXPECT_EQ(RS.cancel_count, (size_t)1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * ruleset_rpcall can also fail after rpcall_finish() already completed the
 * call: the state is detached (ctx->rpcstate NULL, so ruleset_cancel reaches
 * nothing) while w_finish is fed and the result delivered. The failure path
 * answers 500 and leaves STATE_PROCESS, so it must drop that pending event and
 * its result too -- otherwise rpcall_cb runs on a ctx in STATE_RESPONSE, where
 * it aborts on its state assertion and, without one, replaces the error
 * response already composed in wbuf with the rpcall result.
 */
T_DECLARE_CASE(ruleset_rpcall_completed_then_failed_drops_finish)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server api, core;
	int peer_fd = -1;
	unsigned char rsp[4096];
	int ruleset_tag = 0;

	T_CHECK(loop != NULL);
	reset_ruleset_stub();
	RS.loop = loop;
	RS.rpcall_ok = false;
	RS.rpcall_finish_then_fail = true;
	RS.errstr = "rpcall failed";
	RS.errlen = sizeof("rpcall failed") - 1;
	RS.rpcall_result = "rpcall-result-marker";
	RS.rpcall_resultlen = sizeof("rpcall-result-marker") - 1;
	init_server_pair(&api, &core, loop);
	/* the ruleset lives on the core server; api_server reads it there */
	core.ruleset = (struct ruleset *)&ruleset_tag;
	start_api(&api, loop, &peer_fd);

	T_CHECK(send_request(
		peer_fd, "POST /ruleset/rpcall HTTP/1.1\r\nHost: test\r\n"
			 "Content-Length: 1\r\n"
			 "Content-Type: " MIME_RPCALL "\r\n\r\n"
			 "x"));
	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, sizeof(rsp), TEST_WAIT_RECV_SEC);
		T_EXPECT(n > 0);
		T_EXPECT(assert_status(rsp, (size_t)n, " 500 "));
		T_EXPECT(find_bytes(rsp, (size_t)n, "rpcall failed"));
		/* the client is answered once, with the failure */
		T_EXPECT(!find_bytes(rsp, (size_t)n, RS.rpcall_result));
		T_EXPECT(!find_bytes(rsp, (size_t)n, "rpcall did not return"));
	}
	/* the completed call detached its own state; nothing was left to cancel */
	T_EXPECT_EQ(RS.cancel_count, (size_t)0);
	T_EXPECT_EQ(api.stats.num_api_success, (uint_least64_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif /* WITH_RULESET */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(host_validation_before_api_dispatch),
	T_CASE(healthy_keepalive_reuse_connection),
	T_CASE(pipelined_requests_both_answered),
	T_CASE(pipelined_after_body_request_both_answered),
	T_CASE(healthy_request_body_is_not_echoed),
	T_CASE(healthy_connection_close_header),
	T_CASE(api_stats_do_not_pollute_proxy_stats_in_unified_server),
	T_CASE(metrics_keep_proxy_and_api_request_totals_separate),
	T_CASE(metrics_unsupported_accept_encoding_and_te_returns_200),
	T_CASE(metrics_appends_ruleset_metrics_when_defined),
	T_CASE(metrics_float_sample_keeps_full_precision),
	T_CASE(metrics_float_sample_ignores_lc_numeric),
	T_CASE(stats_get_ok_with_nocache),
	T_CASE(stats_output_format_has_no_raw_specifiers),
	T_CASE(stats_post_ok_without_nocache),
	T_CASE(stats_post_without_server_advances_rate_baselines),
	T_CASE(stats_bad_method_405),
	T_CASE(metrics_bad_method_405),
	T_CASE(healthy_bad_method_405),
	T_CASE(stats_trailing_path_404),
	T_CASE(stats_bad_query_400),
	T_CASE(chunked_request_rejected_501),
	T_CASE(stats_key_only_query_options),
	T_CASE(stats_deflate_response_header),
	T_CASE(not_found_404),
	T_CASE(malformed_url_400),
	T_CASE(stats_connect_latency_shows_percentiles),
	T_CASE(stats_nobanner_option_suppresses_banner),
#if WITH_RULESET
	T_CASE(stats_post_with_ruleset_q),
	T_CASE(stats_post_ruleset_dt_is_rate_window),
	T_CASE(stats_post_ruleset_error_in_body),
	T_CASE(healthy_unhealthy_returns_503),
	T_CASE(ruleset_disabled_returns_500),
	T_CASE(ruleset_unknown_action_404),
	T_CASE(ruleset_invoke_ok_200),
	T_CASE(ruleset_invoke_empty_body_ok_200),
	T_CASE(errmsg_content_length_matches_truncated_body),
	T_CASE(ruleset_invoke_length_required_411),
	T_CASE(ruleset_update_ok_contains_time_cost),
	T_CASE(ruleset_update_empty_body_ok_200),
	T_CASE(ruleset_update_fail_500),
	T_CASE(ruleset_update_bad_query_400),
	T_CASE(ruleset_gc_ok_contains_report),
	T_CASE(ruleset_removed_before_processing),
	T_CASE(ruleset_gc_fail_500),
	T_CASE(ruleset_rpcall_bad_mime_400),
	T_CASE(ruleset_rpcall_pending_torn_down_by_timeout),
	T_CASE(ruleset_rpcall_sync_finish_ok_200),
	T_CASE(ruleset_rpcall_finished_torn_down_before_dispatch),
	T_CASE(ruleset_rpcall_ok_deflate_response),
	T_CASE(ruleset_rpcall_empty_body_ok),
	T_CASE(ruleset_rpcall_sync_fail_500),
	T_CASE(ruleset_rpcall_null_result_500),
	T_CASE(ruleset_rpcall_orphaned_state_cancelled),
	T_CASE(ruleset_rpcall_completed_then_failed_drops_finish),
#endif /* WITH_RULESET */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
