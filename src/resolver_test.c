/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * resolver_test - white-box unit tests for resolver.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   resolver.c       module under test
 * Leaf libraries: c-ares.
 * Test-only aliases inject allocation/channel failures, control c-ares
 * deadlines and observe timer rearming;
 * socket processing and libev timer operations still use the real libraries.
 */

#include "resolver.h"

#include "conf.h"

#include "io/memory.h"
#include "io/stream.h"
#include "os/socket.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if WITH_CARES
/* ares.h needs fd_set under strict POSIX feature macros. */
#include <sys/select.h>

#include <ares.h>
#include <ares_version.h>
#endif
#include <sys/time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - deadline control and shared test fixtures.
 * ---------------------------------------------------------------------- */

static bool g_fail_malloc;
static bool g_fail_wait;
static size_t g_resolver_allocations;
static size_t g_fixtures_cleaned;

void *test_resolver_malloc(const size_t size)
{
	if (g_fail_malloc) {
		g_fail_malloc = false;
		return NULL;
	}
	void *const p = malloc(size);
	if (p != NULL) {
		g_resolver_allocations++;
	}
	return p;
}

void test_resolver_free(void *const p)
{
	if (p != NULL) {
		T_CHECK(g_resolver_allocations > 0);
		g_resolver_allocations--;
	}
	free(p);
}

/* The cleanup runs after the case frame has been unwound. Keep the resolver,
 * loop and any active DNS watcher in storage that survives that jump. */
struct resolver_fixture {
	struct ev_loop *loop;
	struct resolver *resolver;
	int dns_fd;
#if WITH_CARES
	ev_io dns_watcher;
	bool dns_watcher_initialized;
	char nameserver[32];
#endif
};

static void fixture_free_resolver(struct resolver_fixture *fixture)
{
	resolver_free(fixture->resolver);
	fixture->resolver = NULL;
}

static void fixture_cleanup(void *data)
{
	struct resolver_fixture *fixture = data;
	fixture_free_resolver(fixture);
#if WITH_CARES
	if (fixture->dns_watcher_initialized) {
		ev_io_stop(fixture->loop, &fixture->dns_watcher);
	}
#endif
	if (fixture->dns_fd >= 0) {
		(void)close(fixture->dns_fd);
	}
	ev_loop_destroy(fixture->loop);
	free(fixture);
	g_fixtures_cleaned++;
}

static struct resolver_fixture *fixture_new(struct testing_ctx *_t_)
{
	struct resolver_fixture *fixture = calloc(1, sizeof(*fixture));
	T_CHECK(fixture != NULL);
	fixture->dns_fd = -1;
	fixture->loop = ev_loop_new(0);
	T_CHECK(fixture->loop != NULL);
	T_CLEANUP(fixture_cleanup, fixture);
	return fixture;
}

/* Failsafe watchdog for the event-driven waits in wait_for_result(): each
 * resolution breaks the loop the instant its completion event fires, so a
 * correct build never reaches this deadline -- it exists only to fail a genuine
 * hang in bounded time instead of blocking CI. It is therefore sized to the
 * project-standard T_TIMEOUT_SECONDS rather than a tight bound: the c-ares
 * fake-nameserver cases run inside c-ares' own retry envelope (up to a few
 * seconds), so a sub-second watchdog supervising them is under-sized and a slow
 * or heavily loaded CI runner can trip it spuriously. */
static const ev_tstamp TEST_WAIT_SEC = (ev_tstamp)T_TIMEOUT_SECONDS;

struct resolve_result {
	bool called;
	bool ok;
	int family;
	uint_least16_t port;
	/* the whole answer, so a case can assert what an unpinned query
	 * carries beyond its first address */
	size_t num_addr;
	union sockaddr_max addr[RESOLVE_MAX_ADDR];
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
	const union sockaddr_max *addr, const size_t num_addr)
{
	struct resolve_result *const result = data;

	(void)q;
	result->called = true;
	result->ok = num_addr > 0;
	result->num_addr = num_addr;
	if (num_addr > 0) {
		/* RESOLVE_MAX_ADDR bounds the answer, and addr[] is that long */
		(void)memcpy(result->addr, addr, num_addr * sizeof(addr[0]));
		const struct sockaddr *const sa = &addr[0].sa;
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
	if (g_fail_wait) {
		g_fail_wait = false;
		return false;
	}
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

/* Dispatch the events already pending in the loop, without blocking.
 * resolve_do() feeds the completion event before it returns, so a caller that
 * asserts a callback did *not* run can drain it here rather than waiting out
 * the watchdog (hitting which is always a failure, never an expected pass). */
static void drain_pending(struct ev_loop *loop)
{
	while (ev_pending_count(loop) > 0) {
		ev_invoke_pending(loop);
	}
}

static struct resolver_fixture *new_test_resolver(struct testing_ctx *_t_)
{
	struct config conf = { 0 };
	struct resolver_fixture *fixture = fixture_new(_t_);
	fixture->resolver = resolver_new(fixture->loop, &conf);
	T_CHECK(fixture->resolver != NULL);
	return fixture;
}

#if WITH_CARES
static bool g_fail_ares_init;
static size_t g_ares_init_calls;
static size_t g_ares_destroy_calls;
static size_t g_ares_set_servers_calls;
static int g_last_dns_fd = -1;

int test_ares_init_options(
	ares_channel *channel, const struct ares_options *options,
	const int optmask)
{
	g_ares_init_calls++;
	if (g_fail_ares_init) {
		g_fail_ares_init = false;
		return ARES_ENOMEM;
	}
	return ares_init_options(channel, options, optmask);
}

void test_ares_destroy(ares_channel channel)
{
	g_ares_destroy_calls++;
	ares_destroy(channel);
}

int test_ares_set_servers_ports_csv(ares_channel channel, const char *servers)
{
	g_ares_set_servers_calls++;
	return ares_set_servers_ports_csv(channel, servers);
}

static struct {
	bool enabled;
	struct timeval next;
	ev_timer *watcher;
} g_timeout;

/* c-ares made the channel parameter const in 1.29. */
struct timeval *test_ares_timeout(
#if ARES_VERSION >= 0x011d00
	const ares_channel_t *channel,
#else
	ares_channel channel,
#endif
	struct timeval *maxtv, struct timeval *tv)
{
	if (!g_timeout.enabled) {
		return ares_timeout(channel, maxtv, tv);
	}
	*tv = g_timeout.next;
	return tv;
}

void test_ev_timer_again(struct ev_loop *loop, ev_timer *watcher)
{
	if (g_timeout.enabled) {
		g_timeout.watcher = watcher;
	}
	ev_timer_again(loop, watcher);
}

static void reset_timeout(void *data)
{
	(void)data;
	memset(&g_timeout, 0, sizeof(g_timeout));
}

/* Log capture, for the cases that point the resolver at a fake nameserver so
 * the host name they log needs no real lookup. A stream sink, not the writer
 * sink the other suites install: only the terminal and stream sinks render a
 * struct slog_extra, and the query name is written there. */
static struct {
	char buf[8192];
	size_t len;
	struct io_stream *stream;
} g_logcap;

static void logcap_start(const int level)
{
	g_logcap.len = 0;
	g_logcap.buf[0] = '\0';
	g_logcap.stream = io_memwriter(
		g_logcap.buf, sizeof(g_logcap.buf) - 1, &g_logcap.len);
	T_CHECK(g_logcap.stream != NULL);
	slog_setoutput(SLOG_OUTPUT_STREAM, g_logcap.stream);
	slog_setlevel(level);
}

/* Restore the default silence, so a case that longjmps out of an assertion
 * cannot leave the stream sink installed for the next one. */
static void logcap_stop(void)
{
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	if (g_logcap.stream != NULL) {
		(void)io_stream_close(g_logcap.stream);
		g_logcap.stream = NULL;
	}
	g_logcap.buf[g_logcap.len] = '\0';
}

/* True when a line slog itself started carries @p needle. Every byte
 * slog_extra_txt writes is indented, so a line beginning at column 0 is one
 * slog composed: peer-supplied text reaching such a line is a forged entry. */
static bool logcap_toplevel_has(const char *restrict needle)
{
	const size_t needlelen = strlen(needle);
	for (const char *line = g_logcap.buf; *line != '\0';) {
		const char *const eol = strchr(line, '\n');
		const size_t linelen =
			(eol != NULL) ? (size_t)(eol - line) : strlen(line);
		if (*line != ' ') {
			for (size_t i = 0; i + needlelen <= linelen; i++) {
				if (memcmp(line + i, needle, needlelen) == 0) {
					return true;
				}
			}
		}
		if (eol == NULL) {
			break;
		}
		line = eol + 1;
	}
	return false;
}
#endif /* WITH_CARES */

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - name resolution success/failure and lifecycle cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(resolver_new_allocation_failure)
{
	struct resolver_fixture *fixture = fixture_new(_t_);
	struct config conf = { 0 };
	const size_t before = g_resolver_allocations;
#if WITH_CARES
	const size_t init_before = g_ares_init_calls;
#endif
	g_fail_malloc = true;
	fixture->resolver = resolver_new(fixture->loop, &conf);
	T_EXPECT(!g_fail_malloc);
	T_EXPECT(fixture->resolver == NULL);
	T_EXPECT_EQ(g_resolver_allocations, before);
	T_EXPECT_EQ(ev_run(fixture->loop, EVRUN_NOWAIT), 0);
#if WITH_CARES
	T_EXPECT_EQ(g_ares_init_calls, init_before);
#endif
	/* The one-shot failure leaves the next construction usable. */
	fixture->resolver = resolver_new(fixture->loop, &conf);
	T_EXPECT(fixture->resolver != NULL);
}

#if WITH_CARES
T_DECLARE_CASE(resolver_channel_failure_uses_synchronous_fallback)
{
	struct resolver_fixture *fixture = fixture_new(_t_);
	struct config conf = { .nameserver = "127.0.0.1:9" };
	const size_t before = g_resolver_allocations;
	const size_t init_before = g_ares_init_calls;
	const size_t destroy_before = g_ares_destroy_calls;
	const size_t servers_before = g_ares_set_servers_calls;
	g_fail_ares_init = true;
	fixture->resolver = resolver_new(fixture->loop, &conf);
	T_CHECK(fixture->resolver != NULL);
	T_EXPECT(!g_fail_ares_init);
	T_EXPECT_EQ(g_ares_init_calls, init_before + 1);
	T_EXPECT_EQ(g_resolver_allocations, before + 1);
	resolver_setnameserver(fixture->resolver, &conf);
	T_EXPECT_EQ(g_ares_set_servers_calls, servers_before);

	struct resolve_result result = { 0 };
	T_CHECK(resolve_do(
			fixture->resolver,
			(struct resolve_cb){ .func = resolve_capture_cb,
					     .data = &result },
			"127.0.0.1", "443", AF_INET) != NULL);
	T_EXPECT(!result.called);
	T_EXPECT(ev_pending_count(fixture->loop) > 0);
	T_EXPECT(wait_for_result(fixture->loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.num_addr, 1);
	T_EXPECT_EQ(result.family, AF_INET);
	T_EXPECT_EQ(result.port, 443);
	T_EXPECT_EQ(result.addr[0].in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
	const struct resolver_stats *stats = resolver_stats(fixture->resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);

	fixture_free_resolver(fixture);
	T_EXPECT_EQ(g_resolver_allocations, before);
	T_EXPECT_EQ(g_ares_destroy_calls, destroy_before);
	T_EXPECT_EQ(g_ares_set_servers_calls, servers_before);
	T_EXPECT_EQ(ev_run(fixture->loop, EVRUN_NOWAIT), 0);
}
#endif /* WITH_CARES */

T_DECLARE_CASE(resolve_success_ipv4)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
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
}

T_DECLARE_CASE(resolve_failure_family_mismatch)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	struct resolve_result result = { 0 };
	const struct resolver_stats *stats;

	/* An IP literal parsed under a mismatched address family is rejected
	 * locally, so this fails deterministically without a network round-trip
	 * -- unlike a bad hostname, whose lookup can stall past the watchdog in an
	 * offline environment. An unknown *service* is not a reliable trigger:
	 * glibc's getaddrinfo rejects it, but c-ares silently ignores it for a
	 * numeric host and succeeds with port 0. An IPv6 literal requested as
	 * AF_INET fails in both backends (c-ares ARES_EBADNAME, glibc
	 * EAI_ADDRFAMILY). */
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"::1", "443", AF_INET) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(!result.ok);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 0);
}

T_DECLARE_CASE(resolve_cancel_suppresses_callback)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
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
	/* the completion event is still pending: cancelling only clears the
	 * callback. Assert it really is pending (so this cannot pass by
	 * draining nothing), dispatch it, and assert it stayed suppressed. */
	T_EXPECT(ev_pending_count(loop) > 0u);
	drain_pending(loop);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(ev_pending_count(loop), 0u);

	/* the lookup itself succeeded: the counters describe it, not whether
	 * anyone was still waiting for the answer */
	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);
}

T_DECLARE_CASE(resolve_success_ipv6)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
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
}

T_DECLARE_CASE(resolve_success_unspec)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
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
}

T_DECLARE_CASE(resolve_success_null_service)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	struct resolve_result result = { 0 };
	const struct resolver_stats *stats;

	/* service == NULL is a documented valid input (resolver.h) and the
	 * pattern production code actually uses (dialer.c dials a hostname with
	 * no service string); exercises the NULL-service resolution path. */
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"127.0.0.1", NULL, AF_INET) != NULL);
	T_EXPECT(wait_for_result(loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.family, AF_INET);
	T_EXPECT_EQ(result.port, 0);

	stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 1);
	T_EXPECT_EQ(stats->num_success, 1);
}

/*
 * Regression: a query that completes synchronously (a literal address is
 * resolved inline) has its finish event deferred but not yet dispatched when
 * resolver_free() runs with no intervening ev_run(). resolver_free() must
 * reclaim it -- neither leaking the query (observable under `m.sh d`) nor
 * invoking its callback.
 */
T_DECLARE_CASE(resolver_free_reclaims_completed_query)
{
	struct resolver_fixture *fixture = new_test_resolver(_t_);
	struct resolver *resolver = fixture->resolver;
	struct resolve_result result = { 0 };

	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"127.0.0.1", "443", AF_INET) != NULL);
	/* free without dispatching the deferred finish event */
	fixture_free_resolver(fixture);
	T_EXPECT(!result.called);
}

#if WITH_CARES
/*
 * A minimal UDP "DNS server" that answers an A or AAAA query with the addresses
 * it was given for that family, used to drive the c-ares socket integration
 * (sock_state_cb / socket_cb) and the getaddrinfo result path that literal-IP
 * lookups never reach. Any other query type is answered with no records, and
 * so is a family it was given no addresses for.
 */
#define FAKE_DNS_MAX_ADDR ((size_t)RESOLVE_MAX_ADDR * 2)

struct fake_dns {
	size_t num_addr;
	struct in_addr addr[FAKE_DNS_MAX_ADDR];
	size_t num_addr6;
	struct in6_addr addr6[FAKE_DNS_MAX_ADDR];
	/* stop watching after one answer, so a case can tell from the watcher
	 * that the reply is on the wire */
	bool once;
};

static void fake_dns_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)revents;
	const struct fake_dns *restrict dns = w->data;
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
	/* QTYPE is the field before QCLASS; 1 is A, 28 is AAAA */
	const unsigned qtype =
		((unsigned)buf[q - 4] << 8) | (unsigned)buf[q - 3];
	size_t num_answer = 0;
	size_t rdlength = 0;
	if (qtype == 1) {
		num_answer = dns->num_addr;
		rdlength = sizeof(dns->addr[0]);
	} else if (qtype == 28) {
		num_answer = dns->num_addr6;
		rdlength = sizeof(dns->addr6[0]);
	}

	unsigned char resp[768];
	size_t len = 0;
	resp[0] = buf[0], resp[1] = buf[1]; /* echo transaction ID */
	resp[2] = 0x81, resp[3] = 0x80; /* QR=1, RD=1, RA=1, RCODE=0 */
	resp[4] = 0x00, resp[5] = 0x01; /* QDCOUNT = 1 */
	resp[6] = 0x00, resp[7] = (unsigned char)num_answer;
	resp[8] = 0x00, resp[9] = 0x00; /* NSCOUNT = 0 */
	resp[10] = 0x00, resp[11] = 0x00; /* ARCOUNT = 0 */
	len = 12;
	memcpy(resp + len, buf + 12, q - 12); /* echo the question */
	len += q - 12;
	for (size_t i = 0; i < num_answer; i++) {
		/* answer: name pointer -> QTYPE IN, TTL 0, the address. The
		 * TTL keeps the c-ares query cache out of a case that resolves
		 * the same name more than once. */
		unsigned char rr[] = {
			0xc0, 0x0c, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		rr[2] = (unsigned char)(qtype >> 8);
		rr[3] = (unsigned char)qtype;
		rr[11] = (unsigned char)rdlength;
		memcpy(resp + len, rr, sizeof(rr));
		len += sizeof(rr);
		if (qtype == 1) {
			memcpy(resp + len, &dns->addr[i], rdlength);
		} else {
			memcpy(resp + len, &dns->addr6[i], rdlength);
		}
		len += rdlength;
	}

	(void)sendto(
		w->fd, resp, len, 0, (const struct sockaddr *)&from, fromlen);
	if (dns->once) {
		ev_io_stop(loop, w);
	}
}

/* The single address the cases below answer with unless they say otherwise. */
static struct fake_dns make_fake_dns(void)
{
	struct fake_dns dns = { .num_addr = 1, .once = true };
	dns.addr[0].s_addr = htonl(0x5DB8D822); /* 93.184.216.34 */
	return dns;
}

/* Bind a UDP socket on an ephemeral loopback port to stand in for a
 * nameserver, and write the `nameserver' string that points a resolver at it.
 * Left unwatched it is a nameserver that never answers; watched with
 * fake_dns_cb it answers from a struct fake_dns. */
static int make_fake_nameserver(char *restrict ns, const size_t nslen)
{
	const int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
	socklen_t addrlen = sizeof(addr);

	T_CHECK(fd >= 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0);
	(void)snprintf(
		ns, nslen, "127.0.0.1:%u", (unsigned)ntohs(addr.sin_port));
	g_last_dns_fd = fd;
	return fd;
}

/* A bound loopback UDP socket keeps unanswered queries hermetic. */
static struct resolver_fixture *
new_dns_resolver(struct testing_ctx *_t_, const bool configure_nameserver)
{
	struct resolver_fixture *fixture = fixture_new(_t_);
	fixture->dns_fd = make_fake_nameserver(
		fixture->nameserver, sizeof(fixture->nameserver));
	struct config conf = {
		.nameserver = configure_nameserver ? fixture->nameserver : NULL,
	};
	fixture->resolver = resolver_new(fixture->loop, &conf);
	T_CHECK(fixture->resolver != NULL);
	return fixture;
}

static ev_io *
fixture_dns_watcher(struct resolver_fixture *fixture, struct fake_dns *dns)
{
	ev_io *watcher = &fixture->dns_watcher;
	ev_io_init(watcher, fake_dns_cb, fixture->dns_fd, EV_READ);
	watcher->data = dns;
	fixture->dns_watcher_initialized = true;
	return watcher;
}

static struct resolve_query *start_unanswered_query(
	struct resolver *resolver, struct resolve_result *result,
	const char *name)
{
	return resolve_do(
		resolver,
		(struct resolve_cb){ .func = resolve_capture_cb,
				     .data = result },
		name, "443", AF_INET);
}

/* Inspect deadlines against libev's cached loop time without running the loop
 * or waiting for c-ares' real retry interval. */
T_DECLARE_CASE(resolve_zero_timeout_keeps_timer_active)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	g_timeout.enabled = true;
	T_CLEANUP(reset_timeout, NULL);
	struct resolve_result result[3] = { 0 };

	T_CHECK(start_unanswered_query(resolver, &result[0], "due.invalid") !=
		NULL);
	T_CHECK(g_timeout.watcher != NULL);
	T_EXPECT(ev_is_active(g_timeout.watcher));
	T_EXPECT(g_timeout.watcher->repeat > 0.0);
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) <= 0.001001);

	g_timeout.next.tv_sec = 60;
	T_CHECK(start_unanswered_query(resolver, &result[1], "later.invalid") !=
		NULL);
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) > 59.0);
	g_timeout.next.tv_sec = 0;
	T_CHECK(start_unanswered_query(
			resolver, &result[2], "due-again.invalid") != NULL);
	T_EXPECT(ev_is_active(g_timeout.watcher));
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) > 0.0);
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) <= 0.001001);
}

T_DECLARE_CASE(resolve_new_query_advances_active_deadline)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	g_timeout.enabled = true;
	g_timeout.next.tv_sec = 60;
	T_CLEANUP(reset_timeout, NULL);
	struct resolve_result result[2] = { 0 };

	T_CHECK(start_unanswered_query(resolver, &result[0], "later.invalid") !=
		NULL);
	T_CHECK(g_timeout.watcher != NULL);
	T_EXPECT(ev_is_active(g_timeout.watcher));
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) > 59.0);
	g_timeout.next = (struct timeval){ .tv_sec = 2, .tv_usec = 500000 };
	T_CHECK(start_unanswered_query(
			resolver, &result[1], "earlier.invalid") != NULL);
	T_EXPECT(ev_is_active(g_timeout.watcher));
	const ev_tstamp remaining = ev_timer_remaining(loop, g_timeout.watcher);
	T_EXPECT(remaining > 2.499 && remaining < 2.501);
	T_EXPECT(!result[0].called && !result[1].called);
}

T_DECLARE_CASE(resolve_socket_event_advances_active_deadline)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	const int dns_fd = fixture->dns_fd;
	g_timeout.enabled = true;
	g_timeout.next.tv_sec = 60;
	T_CLEANUP(reset_timeout, NULL);
	struct resolve_result result[2] = { 0 };
	T_CHECK(start_unanswered_query(resolver, &result[0], "first.invalid") !=
		NULL);
	T_CHECK(start_unanswered_query(
			resolver, &result[1], "second.invalid") != NULL);
	T_CHECK(g_timeout.watcher != NULL);
	T_EXPECT(ev_timer_remaining(loop, g_timeout.watcher) > 59.0);

	/* Reply to only one query. The other remains in flight when socket_cb
	 * must replace the active timer's later deadline. */
	struct fake_dns dns = make_fake_dns();
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	struct pollfd pending = { .fd = dns_fd, .events = POLLIN };
	T_CHECK(poll(&pending, 1, 0) == 1);
	ev_invoke(loop, w_dns, EV_READ);
	g_timeout.next.tv_sec = 5;
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT_EQ(resolver_stats(resolver)->num_success, 1);
	T_EXPECT(ev_is_active(g_timeout.watcher));
	const ev_tstamp remaining = ev_timer_remaining(loop, g_timeout.watcher);
	T_EXPECT(remaining > 4.999 && remaining < 5.001);
}

/*
 * The dialer resolves the name its peer wrote, and a SOCKS5 DOMAINNAME is a
 * length-prefixed byte string (RFC 1928, 5) with no character set of its own.
 * Splicing it into a log line with %s let a newline in it end the line, so
 * everything after it became a line of the peer's own -- at whatever level and
 * severity it chose (CWE-117). Every line the resolver writes about a query
 * must therefore keep the name out of the line itself, while still logging it.
 */
T_DECLARE_CASE(resolve_log_keeps_client_name_off_the_line)
{
	/* a newline that ends the line, plus a CR and a control byte */
	static const char hostile[] = "evil.example\nE forged\rentry\x01";
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct resolver *resolver = fixture->resolver;
	struct resolve_result result = { 0 };

	logcap_start(LOG_LEVEL_DEBUG);
	/* start and cancel both log, and both are synchronous: no lookup has
	 * to complete for the lines under test to be written */
	struct resolve_query *const q = resolve_do(
		resolver,
		(struct resolve_cb){
			.func = resolve_capture_cb,
			.data = &result,
		},
		hostile, NULL, AF_INET);
	T_CHECK(q != NULL);
	resolve_cancel(q);
	logcap_stop();

	T_EXPECT(!logcap_toplevel_has("evil.example"));
	T_EXPECT(!logcap_toplevel_has("forged"));
	/* the name is still logged, just not as part of a line */
	T_EXPECT(strstr(g_logcap.buf, "evil.example") != NULL);
	/* and the bytes that would drive a terminal or a log parser are gone */
	T_EXPECT(memchr(g_logcap.buf, '\r', g_logcap.len) == NULL);
	T_EXPECT(memchr(g_logcap.buf, '\x01', g_logcap.len) == NULL);
}

/* The counterpart: an ordinary name must still read as it always did. */
T_DECLARE_CASE(resolve_log_keeps_an_ordinary_name_legible)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct resolver *resolver = fixture->resolver;
	struct resolve_result result = { 0 };

	logcap_start(LOG_LEVEL_DEBUG);
	struct resolve_query *const q = resolve_do(
		resolver,
		(struct resolve_cb){
			.func = resolve_capture_cb,
			.data = &result,
		},
		"ok.example", NULL, AF_INET);
	T_CHECK(q != NULL);
	resolve_cancel(q);
	logcap_stop();

	T_EXPECT(strstr(g_logcap.buf, "resolve `:': start pf=") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "resolve `:': cancel") != NULL);
	/* rendered whole, on the extra's first line */
	T_EXPECT(strstr(g_logcap.buf, "1 ok.example\n") != NULL);
}

T_DECLARE_CASE(resolve_via_fake_nameserver)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	struct fake_dns dns = make_fake_dns();
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

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

	ev_io_stop(loop, w_dns);
}

/* Resolve `test.invalid' in one family and hand back what the answer carried. */
T_DECLARE_SUBCASE(
	expect_resolve, struct ev_loop *restrict loop,
	struct resolver *restrict resolver, const int family,
	struct resolve_result *restrict result)
{
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = result,
			},
			"test.invalid", "443", family) != NULL);
	T_EXPECT(wait_for_result(loop, result));
	T_EXPECT(result->ok);
}

/*
 * Regression: only the first address of an answer used to reach the caller, so
 * a name whose first address is unreachable failed outright with no second one
 * to fall back to. An unpinned query carries the whole answer now. A query
 * pinned to one family still answers with a single address, which is what
 * `-4' / `-6' has always meant: the operator naming the family to dial in, not
 * the one to start with.
 */
T_DECLARE_CASE(resolve_unpinned_query_carries_every_address)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	/* two addresses for one name, the everyday shape of a CDN record set
	 * and of a dual-stack host alike */
	struct fake_dns dns = { .num_addr = 2 };
	dns.addr[0].s_addr = htonl(0x5DB8D822); /* 93.184.216.34 */
	dns.addr[1].s_addr = htonl(0x5DB8D823); /* 93.184.216.35 */
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

	struct resolve_result unpinned = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_UNSPEC, &unpinned);
	T_EXPECT_EQ(unpinned.num_addr, 2);
	if (unpinned.num_addr == 2) {
		/* both addresses, each carrying the service's port; their
		 * order is the resolver's own and not asserted here */
		T_EXPECT_EQ(unpinned.addr[0].sa.sa_family, AF_INET);
		T_EXPECT_EQ(unpinned.addr[1].sa.sa_family, AF_INET);
		T_EXPECT(
			unpinned.addr[0].in.sin_addr.s_addr !=
			unpinned.addr[1].in.sin_addr.s_addr);
		T_EXPECT_EQ(ntohs(unpinned.addr[1].in.sin_port), 443);
	}

	struct resolve_result pinned = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_INET, &pinned);
	T_EXPECT_EQ(pinned.num_addr, 1);

	ev_io_stop(loop, w_dns);
}

/* Serve @p num4 A records (192.0.2.1, ...) and @p num6 AAAA records
 * (2001:db8::1, ...) for every name. */
static void fake_dns_serve(
	struct fake_dns *restrict dns, const size_t num4, const size_t num6)
{
	T_CHECK(num4 <= FAKE_DNS_MAX_ADDR && num6 <= FAKE_DNS_MAX_ADDR);
	*dns = (struct fake_dns){ .num_addr = num4, .num_addr6 = num6 };
	for (size_t i = 0; i < num4; i++) {
		dns->addr[i].s_addr = htonl(0xC0000201 + (uint_least32_t)i);
	}
	for (size_t i = 0; i < num6; i++) {
		dns->addr6[i].s6_addr[0] = 0x20;
		dns->addr6[i].s6_addr[1] = 0x01;
		dns->addr6[i].s6_addr[2] = 0x0d;
		dns->addr6[i].s6_addr[3] = 0xb8;
		dns->addr6[i].s6_addr[15] = (unsigned char)(i + 1);
	}
}

static size_t
count_family(const struct resolve_result *restrict result, const int family)
{
	size_t n = 0;
	for (size_t i = 0; i < result->num_addr; i++) {
		if (result->addr[i].sa.sa_family == family) {
			n++;
		}
	}
	return n;
}

/* Every address of an answer carries the service's port. */
static bool all_ports_are(
	const struct resolve_result *restrict result, const uint_least16_t port)
{
	for (size_t i = 0; i < result->num_addr; i++) {
		const union sockaddr_max *const a = &result->addr[i];
		const uint_least16_t p = (a->sa.sa_family == AF_INET6) ?
						 ntohs(a->in6.sin6_port) :
						 ntohs(a->in.sin_port);
		if (p != port) {
			return false;
		}
	}
	return true;
}

/*
 * An unpinned query over a dual-stack answer alternates the families (RFC 8305
 * 4), whichever of them the resolver's own ordering put first, and carries no
 * more than RESOLVE_MAX_ADDR of the six addresses served.
 */
T_DECLARE_CASE(resolve_unpinned_query_interleaves_families)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	struct fake_dns dns;
	fake_dns_serve(&dns, 3, 3);
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

	struct resolve_result result = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_UNSPEC, &result);
	T_EXPECT_EQ(result.num_addr, RESOLVE_MAX_ADDR);
	for (size_t i = 1; i < result.num_addr; i++) {
		T_EXPECT(
			result.addr[i].sa.sa_family !=
			result.addr[i - 1].sa.sa_family);
	}
	T_EXPECT_EQ(count_family(&result, AF_INET), RESOLVE_MAX_ADDR / 2);
	T_EXPECT_EQ(count_family(&result, AF_INET6), RESOLVE_MAX_ADDR / 2);
	T_EXPECT(all_ports_are(&result, 443));

	ev_io_stop(loop, w_dns);
}

/* Serve @p num4 A and @p num6 AAAA records, one of the two a single record, and
 * expect that single one among the addresses an unpinned query answers with,
 * in the first or the second slot. */
T_DECLARE_SUBCASE(
	expect_minority_family, struct ev_loop *restrict loop,
	struct resolver *restrict resolver, struct fake_dns *restrict dns,
	const size_t num4, const size_t num6)
{
	fake_dns_serve(dns, num4, num6);
	const int minority = (num4 == 1) ? AF_INET : AF_INET6;
	struct resolve_result result = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_UNSPEC, &result);
	T_EXPECT_EQ(result.num_addr, RESOLVE_MAX_ADDR);
	T_EXPECT_EQ(count_family(&result, minority), 1);
	if (result.num_addr >= 2) {
		T_EXPECT(
			result.addr[0].sa.sa_family !=
			result.addr[1].sa.sa_family);
	}
	T_EXPECT(all_ports_are(&result, 443));
}

/*
 * Regression: the answer used to be cut to twice RESOLVE_MAX_ADDR before its
 * families were interleaved. The resolver's own ordering (RFC 6724) groups the
 * families, so a name with that many records of the leading family never
 * contributed the other family at all. Both shapes are served, so the one whose
 * heavy family leads is covered whichever family this host prefers. A pinned
 * query still answers with one address of its family.
 */
T_DECLARE_CASE(resolve_unpinned_query_keeps_the_minority_family)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	struct fake_dns dns;
	fake_dns_serve(&dns, 0, 0);
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

	T_CALL_SUBCASE(
		expect_minority_family, loop, resolver, &dns, FAKE_DNS_MAX_ADDR,
		1);
	T_CALL_SUBCASE(
		expect_minority_family, loop, resolver, &dns, 1,
		FAKE_DNS_MAX_ADDR);

	fake_dns_serve(&dns, FAKE_DNS_MAX_ADDR, FAKE_DNS_MAX_ADDR);
	struct resolve_result pinned4 = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_INET, &pinned4);
	T_EXPECT_EQ(pinned4.num_addr, 1);
	T_EXPECT_EQ(pinned4.family, AF_INET);
	struct resolve_result pinned6 = { 0 };
	T_CALL_SUBCASE(expect_resolve, loop, resolver, AF_INET6, &pinned6);
	T_EXPECT_EQ(pinned6.num_addr, 1);
	T_EXPECT_EQ(pinned6.family, AF_INET6);

	ev_io_stop(loop, w_dns);
}

/*
 * Regression: resolver_free() must not leak a query that is still in
 * flight when the c-ares channel is destroyed. The "nameserver" here is
 * a bound but unanswered UDP socket, so the query genuinely never
 * completes on its own -- resolver_free() must be what ends it, via
 * ARES_EDESTRUCTION. Per resolver.h, the callback must not fire either;
 * the leak itself is only observable under a leak-detecting build (e.g.
 * `m.sh d`).
 */
T_DECLARE_CASE(resolver_free_does_not_leak_inflight_query)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	struct resolve_result result = { 0 };
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &result,
			},
			"test.invalid", "443", AF_INET) != NULL);

	/* let the query reach the wire without ever answering it, then
	 * destroy the resolver while it is still in flight */
	ev_run(loop, EVRUN_NOWAIT);
	fixture_free_resolver(fixture);
	T_EXPECT(!result.called);
	/* resolver_free() must also leave the loop holding no watcher of the
	 * freed resolver -- an armed w_timeout would fire timeout_cb on freed
	 * storage on any later iteration. Nothing else in this case is started
	 * in the loop, so ev_run's active-watcher count is exactly that check. */
	T_EXPECT_EQ(ev_run(loop, EVRUN_NOWAIT), 0);
}

/*
 * #177: cancelling a query while its c-ares lookup is still on the wire, then
 * letting the answer arrive, must suppress the callback (addrinfo_cb ->
 * finish_defer -> finish_cb sees the cleared done_cb and frees the query). This
 * is distinct from cancelling a synchronously-completed query and from
 * destroying the resolver mid-flight.
 */
T_DECLARE_CASE(resolve_cancel_inflight_suppresses_callback)
{
	struct resolver_fixture *fixture = new_dns_resolver(_t_, true);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;

	struct fake_dns dns = make_fake_dns();
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

	struct resolve_result result = { 0 };
	struct resolve_query *const query = resolve_do(
		resolver,
		(struct resolve_cb){
			.func = resolve_capture_cb,
			.data = &result,
		},
		"test.invalid", "443", AF_INET);
	T_CHECK(query != NULL);

	/* cancel while the query is still on the wire (unanswered) */
	resolve_cancel(query);

	/* pump (blocking, watchdog-bounded) until the fake server answers */
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && ev_is_active(w_dns)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	/* fake_dns_cb stops itself once it has answered: the reply for the
	 * cancelled query is now queued on the c-ares socket */
	T_CHECK(!ev_is_active(w_dns));

	/* Anchor the negative assertion on an observable event instead of a
	 * fixed number of sweeps: a second, uncancelled query answered by the
	 * same fake server. Its reply cannot even be sent before the loop runs
	 * again, while the cancelled query's reply is already waiting, so
	 * c-ares processes the cancelled query -- addrinfo_cb, finish_defer,
	 * finish_cb -- strictly before the tracer's callback breaks the wait. */
	ev_io_start(loop, w_dns);
	struct resolve_result tracer = { 0 };
	T_CHECK(resolve_do(
			resolver,
			(struct resolve_cb){
				.func = resolve_capture_cb,
				.data = &tracer,
			},
			"tracer.invalid", "443", AF_INET) != NULL);
	T_EXPECT(wait_for_result(loop, &tracer));
	T_EXPECT(tracer.ok);

	/* the cancelled query's callback must never have fired, yet its
	 * lookup succeeded and is counted as such */
	T_EXPECT(!result.called);
	const struct resolver_stats *const stats = resolver_stats(resolver);
	T_EXPECT_EQ(stats->num_query, 2);
	T_EXPECT_EQ(stats->num_success, 2);

	ev_io_stop(loop, w_dns);
}

/*
 * Regression: resolver_new() snapshots conf->nameserver at creation, before a
 * boot config could supply one. resolver_setnameserver() must re-apply a
 * nameserver provided only afterwards. The resolver is created with no
 * nameserver, the fake server is applied via resolver_setnameserver(), and the
 * lookup is then answered by it -- which happens only if the re-apply took
 * effect (ares_set_servers_ports_csv replaces the server list).
 */
T_DECLARE_CASE(resolver_setnameserver_applies_after_new)
{
	/* resolver_new sees no nameserver, as it does before a boot config loads */
	struct resolver_fixture *fixture = new_dns_resolver(_t_, false);
	struct ev_loop *loop = fixture->loop;
	struct resolver *resolver = fixture->resolver;
	/* the nameserver becomes known only now, e.g. from a boot config */
	struct config conf = { .nameserver = fixture->nameserver };
	resolver_setnameserver(resolver, &conf);

	struct fake_dns dns = make_fake_dns();
	ev_io *w_dns = fixture_dns_watcher(fixture, &dns);
	ev_io_start(loop, w_dns);

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

	ev_io_stop(loop, w_dns);
}
#endif /* WITH_CARES */

/* Fail an existing result expectation while its query is still owned by the
 * resolver, then rerun the same case successfully in a fresh fixture. */
T_DECLARE_CASE(resolver_failed_expectation_cleans_fixture)
{
	const size_t allocations_before = g_resolver_allocations;
	const size_t cleaned_before = g_fixtures_cleaned;
	T_DECLARE_CTX(nested);
	g_fail_wait = true;
	T_RUN_CASE(nested, resolve_success_ipv4);
	T_EXPECT(!g_fail_wait);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(g_fixtures_cleaned, cleaned_before + 1);
	T_EXPECT_EQ(g_resolver_allocations, allocations_before);
	T_RUN_CASE(nested, resolve_success_ipv4);
	T_EXPECT_EQ(nested.passed, 1);
	T_EXPECT_EQ(g_fixtures_cleaned, cleaned_before + 2);
	T_EXPECT_EQ(g_resolver_allocations, allocations_before);
#if WITH_CARES
	/* Both the direct expectation and expect_resolve's subcase must unwind
	 * through their caller's registered fixture cleanup. */
	for (int i = 0; i < 2; i++) {
		const size_t cleaned = g_fixtures_cleaned;
		g_fail_wait = true;
		if (i == 0) {
			T_RUN_CASE(nested, resolve_via_fake_nameserver);
		} else {
			T_RUN_CASE(
				nested,
				resolve_unpinned_query_carries_every_address);
		}
		T_EXPECT(!g_fail_wait);
		T_EXPECT_EQ(nested.failed, (size_t)i + 2);
		T_EXPECT_EQ(g_fixtures_cleaned, cleaned + 1);
		T_EXPECT_EQ(g_resolver_allocations, allocations_before);
		errno = 0;
		T_EXPECT_EQ(fcntl(g_last_dns_fd, F_GETFD), -1);
		T_EXPECT_EQ(errno, EBADF);
		if (i == 0) {
			T_RUN_CASE(nested, resolve_via_fake_nameserver);
		} else {
			T_RUN_CASE(
				nested,
				resolve_unpinned_query_carries_every_address);
		}
		T_EXPECT_EQ(nested.passed, (size_t)i + 2);
		T_EXPECT_EQ(g_fixtures_cleaned, cleaned + 2);
		T_EXPECT_EQ(g_resolver_allocations, allocations_before);
	}
#endif /* WITH_CARES */
}

T_DECLARE_CASE(resolve_query_allocation_failure_recovers)
{
	struct resolver_fixture *f = fixture_new(_t_);
	struct config conf = { 0 };
	f->resolver = resolver_new(f->loop, &conf);
	T_CHECK(f->resolver != NULL);
	const size_t before = g_resolver_allocations;
	const struct resolver_stats stats_before = *resolver_stats(f->resolver);
	struct resolve_result result = { 0 };
	const struct resolve_cb cb = { .func = resolve_capture_cb,
				       .data = &result };
	g_fail_malloc = true;
	struct resolve_query *query =
		resolve_do(f->resolver, cb, "127.0.0.1", "443", AF_INET);
	T_EXPECT(!g_fail_malloc);
	T_EXPECT(query == NULL);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(g_resolver_allocations, before);
	T_EXPECT_EQ(
		resolver_stats(f->resolver)->num_query, stats_before.num_query);
	T_EXPECT_EQ(ev_pending_count(f->loop), 0);
	T_EXPECT_EQ(ev_run(f->loop, EVRUN_NOWAIT), 0);
	T_CHECK(resolve_do(f->resolver, cb, "127.0.0.1", "443", AF_INET) !=
		NULL);
	T_EXPECT(wait_for_result(f->loop, &result));
	T_EXPECT(result.ok);
	T_EXPECT_EQ(result.port, 443);
	T_EXPECT_EQ(g_resolver_allocations, before);
	T_EXPECT_EQ(
		resolver_stats(f->resolver)->num_query,
		stats_before.num_query + 1);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(resolve_query_allocation_failure_recovers),
	T_CASE(resolver_new_allocation_failure),
	T_CASE(resolver_failed_expectation_cleans_fixture),
#if WITH_CARES
	T_CASE(resolver_channel_failure_uses_synchronous_fallback),
#endif
	T_CASE(resolve_success_ipv4),
	T_CASE(resolve_failure_family_mismatch),
	T_CASE(resolve_cancel_suppresses_callback),
	T_CASE(resolve_success_ipv6),
	T_CASE(resolve_success_unspec),
	T_CASE(resolve_success_null_service),
	T_CASE(resolver_free_reclaims_completed_query),
#if WITH_CARES
	T_CASE(resolve_zero_timeout_keeps_timer_active),
	T_CASE(resolve_new_query_advances_active_deadline),
	T_CASE(resolve_socket_event_advances_active_deadline),
	T_CASE(resolve_log_keeps_client_name_off_the_line),
	T_CASE(resolve_log_keeps_an_ordinary_name_legible),
	T_CASE(resolve_via_fake_nameserver),
	T_CASE(resolve_unpinned_query_carries_every_address),
	T_CASE(resolve_unpinned_query_interleaves_families),
	T_CASE(resolve_unpinned_query_keeps_the_minority_family),
	T_CASE(resolver_free_does_not_leak_inflight_query),
	T_CASE(resolve_cancel_inflight_suppresses_callback),
	T_CASE(resolver_setnameserver_applies_after_new),
#endif /* WITH_CARES */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	resolver_init();
	const int ret = testing_main(argc, argv, suite);
	resolver_cleanup();
	return ret;
}
