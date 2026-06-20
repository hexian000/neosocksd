/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * resolver_test - white-box unit tests for resolver.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   resolver.c       module under test
 * Leaf libraries: c-ares.
 * resolver.c has no stateful collaborator module to mock; the mock section
 * only holds shared test fixtures.
 */

#include "conf.h"
#include "resolver.h"

#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared test fixtures (resolver.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - name resolution success/failure and lifecycle cases.
 * ---------------------------------------------------------------------- */

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

T_DECLARE_CASE(resolve_success_ipv6)
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
			"::1", "443", AF_INET6) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.family, AF_INET6);
	T_EXPECT_EQ(result.port, 443);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);

	free_test_resolver(resolver, loop);
}

T_DECLARE_CASE(resolve_success_unspec)
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
			"127.0.0.1", "80", AF_UNSPEC) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT(result.family == AF_INET || result.family == AF_INET6);
	T_EXPECT_EQ(result.port, 80);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);

	free_test_resolver(resolver, loop);
}

#if WITH_CARES
/*
 * A minimal UDP "DNS server" that answers a single A query, used to drive the
 * c-ares socket integration (sock_state_cb / socket_cb) and the getaddrinfo
 * result path that literal-IP lookups never reach.
 */
static void fake_dns_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)revents;
	unsigned char buf[512];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	const ssize_t n = recvfrom(
		w->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
	if (n < 12) {
		return;
	}
	/* locate the end of the question (QNAME + QTYPE + QCLASS) */
	size_t q = 12;
	while (q < (size_t)n && buf[q] != 0) {
		q += (size_t)buf[q] + 1;
	}
	q += 1 + 4;
	if (q > (size_t)n) {
		return;
	}

	unsigned char resp[600];
	size_t len = 0;
	resp[0] = buf[0], resp[1] = buf[1]; /* echo transaction ID */
	resp[2] = 0x81, resp[3] = 0x80; /* QR=1, RD=1, RA=1, RCODE=0 */
	resp[4] = 0x00, resp[5] = 0x01; /* QDCOUNT = 1 */
	resp[6] = 0x00, resp[7] = 0x01; /* ANCOUNT = 1 */
	resp[8] = 0x00, resp[9] = 0x00; /* NSCOUNT = 0 */
	resp[10] = 0x00, resp[11] = 0x00; /* ARCOUNT = 0 */
	len = 12;
	memcpy(resp + len, buf + 12, q - 12); /* echo the question */
	len += q - 12;
	/* answer: name pointer -> A IN, TTL 60, 93.184.216.34 */
	const unsigned char answer[] = {
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x3c, 0x00, 0x04, 93,   184,  216,  34,
	};
	memcpy(resp + len, answer, sizeof(answer));
	len += sizeof(answer);

	(void)sendto(
		w->fd, resp, len, 0, (const struct sockaddr *)&from, fromlen);
	ev_io_stop(loop, w);
}

T_DECLARE_CASE(resolve_via_fake_nameserver)
{
	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	/* bind a UDP socket on an ephemeral loopback port to act as a server */
	const int dns_fd = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(dns_fd >= 0);
	struct sockaddr_in dns_addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
	T_CHECK(bind(dns_fd, (const struct sockaddr *)&dns_addr,
		     sizeof(dns_addr)) == 0);
	socklen_t addrlen = sizeof(dns_addr);
	T_CHECK(getsockname(dns_fd, (struct sockaddr *)&dns_addr, &addrlen) ==
		0);

	char nameserver[32];
	(void)snprintf(
		nameserver, sizeof(nameserver), "127.0.0.1:%u",
		(unsigned)ntohs(dns_addr.sin_port));
	struct config conf = { .nameserver = nameserver };
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	ev_io_start(loop, &w_dns);

	struct resolve_result result = { 0 };
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"test.invalid", "443", AF_INET) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.family, AF_INET);
	T_EXPECT_EQ(result.port, 443);

	const struct resolver_stats *const stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);

	ev_io_stop(loop, &w_dns);
	(void)close(dns_fd);
	resolver_free(resolver);
	ev_loop_destroy(loop);
}
#endif /* WITH_CARES */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

int main(void)
{
	T_DECLARE_CTX(t);

	resolver_init();
	T_RUN_CASE(t, resolve_success_ipv4);
	T_RUN_CASE(t, resolve_failure_invalid_name);
	T_RUN_CASE(t, resolve_cancel_suppresses_callback);
	T_RUN_CASE(t, resolve_success_ipv6);
	T_RUN_CASE(t, resolve_success_unspec);
#if WITH_CARES
	T_RUN_CASE(t, resolve_via_fake_nameserver);
#endif
	resolver_cleanup();
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
