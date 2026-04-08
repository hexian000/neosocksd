/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "resolver.h"

#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>

static const ev_tstamp TEST_WAIT_SEC = 0.5;

struct resolve_result {
	bool called;
	bool ok;
	int family;
	unsigned port;
};

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

static void resolve_capture_cb(
	struct resolve_query *q, struct ev_loop *loop, void *data,
	const struct sockaddr *sa)
{
	struct resolve_result *const result = data;

	(void)q;
	result->called = true;
	result->ok = sa != NULL;
	if (sa != NULL) {
		result->family = sa->sa_family;
		switch (sa->sa_family) {
		case AF_INET:
			result->port = ntohs(
				((const struct sockaddr_in *)sa)->sin_port);
			break;
		case AF_INET6:
			result->port = ntohs(
				((const struct sockaddr_in6 *)sa)->sin6_port);
			break;
		default:
			result->family = -1;
			result->port = 0;
			break;
		}
	}
	ev_break(loop, EVBREAK_ONE);
}

static bool wait_for_result(struct ev_loop *loop, struct resolve_result *result)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && !result->called) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return result->called;
}

static struct resolver *new_test_resolver(struct ev_loop **loop_out)
{
	struct config conf = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	struct resolver *resolver;

	T_CHECK(loop != NULL);
	resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	*loop_out = loop;
	return resolver;
}

static void free_test_resolver(struct resolver *resolver, struct ev_loop *loop)
{
	resolver_free(resolver);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(resolve_success_ipv4)
{
	struct ev_loop *loop = NULL;
	struct resolver *const resolver = new_test_resolver(&loop);
	struct resolve_result result = { 0 };
	const struct resolver_stats *stats;

	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"127.0.0.1", "443", AF_INET) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.family, AF_INET);
	T_EXPECT_EQ(result.port, 443);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);

	free_test_resolver(resolver, loop);
}

T_DECLARE_CASE(resolve_failure_invalid_name)
{
	struct ev_loop *loop = NULL;
	struct resolver *const resolver = new_test_resolver(&loop);
	struct resolve_result result = { 0 };
	const struct resolver_stats *stats;

	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"bad host", "443", AF_UNSPEC) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(!result.ok);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 0);

	free_test_resolver(resolver, loop);
}

T_DECLARE_CASE(resolve_cancel_suppresses_callback)
{
	struct ev_loop *loop = NULL;
	struct resolver *const resolver = new_test_resolver(&loop);
	struct resolve_result result = { 0 };
	struct resolve_query *query;
	const struct resolver_stats *stats;

	query = resolve_do(
		resolver,
		(struct resolve_cb){
			.func = resolve_capture_cb,
			.data = &result,
		},
		"127.0.0.1", "443", AF_INET);
	T_CHECK(query != NULL);
	resolve_cancel(query);
	resolve_cancel(query);
	T_EXPECT(!wait_for_result(loop, &result));
	T_EXPECT(!result.called);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 0);

	free_test_resolver(resolver, loop);
}

int main(void)
{
	T_DECLARE_CTX(t);

	resolver_init();
	T_RUN_CASE(t, resolve_success_ipv4);
	T_RUN_CASE(t, resolve_failure_invalid_name);
	T_RUN_CASE(t, resolve_cancel_suppresses_callback);
	resolver_cleanup();
	return !T_RESULT(t);
}
