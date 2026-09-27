/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for dialer.c; mocked: HTTP/SOCKS peers (hand-rolled over sockets). */

#include "dialer.h"

#include "conf.h"
#include "proto/domain.h"
#include "proto/socks.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "io/memory.h"
#include "io/stream.h"
#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
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
 * mock - raw loopback proxy peers and shared fixtures (no collaborator module
 * is linked; the dialer's peers are hand-rolled over socketpairs/listeners).
 * ---------------------------------------------------------------------- */

/* The configuration every case dials with. The dialer arms no deadline of its
 * own -- each owner (socks.c, http_proxy.c, forward.c, ruleset/await.c) wraps
 * its dial in a conf->timeout watchdog and cancels the dialer when it fires --
 * so conf.timeout is not read from here. What the dialer does read (the egress
 * policy flags, resolve_pf, the socket options) is left at its zero default;
 * a case needing otherwise copies this and sets the one field it exercises. */
static const struct config test_conf = { 0 };

/* Failsafe watchdog for the event-driven waits below: every case breaks its
 * loop the instant the dialer's callback fires, so a correct build never
 * reaches this deadline -- it exists only to fail a genuine hang in bounded
 * time instead of blocking CI. It is therefore sized to the project-standard
 * T_TIMEOUT_SECONDS rather than a tight bound: a sub-second watchdog is
 * under-sized here, because scheduling delay alone can stretch a healthy dial
 * past it on a loaded runner and fail it spuriously. */
static const ev_tstamp TEST_WAIT_SEC = (ev_tstamp)T_TIMEOUT_SECONDS;
/* Short tick so ev_run() wakes promptly when mock servers write in fragments
 * (needed for MSYS2/Cygwin socket emulation). It also bounds how long one
 * test_wait_until() iteration can take, and a mock server delivers at most one
 * chunk per iteration, so it caps the trickle rate: keep it well below the
 * per-round allowance proxy_server_wait_sec() grants. */
static const ev_tstamp TEST_TICK_SEC = 0.0002;

struct dialer_result {
	bool called;
	int fd;
};

struct test_watchdog {
	bool fired;
};

struct proxy_server {
	int listener_fd;
	int peer_fd;
	char request[1024];
	size_t request_len;
	const char *response;
	/* Bytes of `response` written per pump() call once the request is
	 * complete; 0 (the default) sends the whole response in one write,
	 * matching every existing test. A nonzero value spreads delivery
	 * across multiple dialer_recv() events, e.g. to reproduce bugs in
	 * how partial reads are accounted for. */
	size_t response_chunk;
	size_t response_off;
	/* tunnel bytes sent in the same write as the response's last piece,
	 * as the destination's first bytes follow a 2xx (default none) */
	const unsigned char *payload;
	size_t payload_len;
	bool request_complete;
	bool response_sent;
	bool failed;
};

static void close_if_open(int *restrict fd)
{
	if (*fd >= 0) {
		T_CHECK(close(*fd) == 0);
		*fd = -1;
	}
}

static void dialer_finish_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct dialer_result *const result = data;
	(void)loop;
	result->called = true;
	result->fd = fd;
}

static bool dialer_called_predicate(void *data)
{
	const struct dialer_result *const result = data;
	return result->called;
}

static void
test_watchdog_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	struct test_watchdog *const watchdog = w->data;
	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
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
	struct ev_loop *loop, bool (*predicate)(void *), void *predicate_data,
	const ev_tstamp timeout_sec, bool (*step)(void *), void *step_data)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;
	bool ok = true;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	/* Bound ev_run() sleeps so the step callback (an unwatched mock server)
	 * keeps getting serviced even while the dialer waits on a reply. */
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && !predicate(predicate_data) && ok) {
		ev_run(loop, EVRUN_ONCE);
		if (step != NULL) {
			ok = step(step_data);
		}
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return ok && predicate(predicate_data);
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/* connect() test stub. The dialer sets the socket non-blocking, so
 * a real connect() to a loopback listener always returns EINPROGRESS,
 * exercising only connect_sa()'s async EV_WRITE path. When g_force_sync_connect
 * is set, block to completion so connect() returns 0 with a ready socket,
 * driving the connect()-returns-0 + num_proxy>0 handshake branch instead.
 * Default calls pass through unchanged. */
static bool g_force_sync_connect = false;
static int g_sync_connect_ret = -2; /* sentinel: sync connect not attempted */
/* When set, fail connect() synchronously with ECONNREFUSED without touching the
 * network, so a test can observe "passed the egress check and reached connect"
 * for an address that has no reachable listener (e.g. CGNAT space). */
static bool g_force_connect_fail = false;

int test_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (g_force_connect_fail) {
		(void)fd, (void)addr, (void)addrlen;
		errno = ECONNREFUSED;
		return -1;
	}
	if (!g_force_sync_connect) {
		return connect(fd, addr, addrlen);
	}
	const int flags = fcntl(fd, F_GETFL, 0);
	(void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	const int ret = connect(fd, addr, addrlen);
	(void)fcntl(fd, F_SETFL, flags);
	g_sync_connect_ret = ret;
	return ret;
}

/* malloc() test stub. dialreq_parse() sizes
 * proxy[] from the comma count of an operator-supplied string, so a case has to
 * observe the size it asks for -- not merely that an over-long chain is
 * rejected. Only the calling thread runs while tracking is armed. */
static size_t g_malloc_peak;
static bool g_malloc_track;
/* When set, the next malloc() fails and the flag clears itself, so exactly one
 * allocation -- the one the arming case is about -- is forced out of memory. */
static bool g_malloc_fail_once;

void *test_malloc(const size_t size)
{
	if (g_malloc_fail_once) {
		g_malloc_fail_once = false;
		return NULL;
	}
	if (g_malloc_track && size > g_malloc_peak) {
		g_malloc_peak = size;
	}
	return malloc(size);
}

/* The test build redirects dialer.c's socket setters to these stubs.
 * Fixture and pass-through calls still use the real csnippets functions. They
 * return 0 or an errno and promise nothing about the global errno, so an armed
 * failure returns its own errno and leaves STALE_ERRNO in the global one.
 * Unarmed calls pass through unchanged. */
int test_socket_set_cloexec(int fd);
int test_socket_set_nonblock(int fd);

/* no socket setup can fail this way, so a report of it can only have come from
 * the global errno */
enum { STALE_ERRNO = EDOM };

/* one-shot failures; 0 lets the call through */
static int g_cloexec_fail_errno;
static int g_nonblock_fail_errno;

int test_socket_set_cloexec(const int fd)
{
	const int err = g_cloexec_fail_errno;
	if (err == 0) {
		return socket_set_cloexec(fd);
	}
	g_cloexec_fail_errno = 0;
	errno = STALE_ERRNO;
	return err;
}

int test_socket_set_nonblock(const int fd)
{
	const int err = g_nonblock_fail_errno;
	if (err == 0) {
		return socket_set_nonblock(fd);
	}
	g_nonblock_fail_errno = 0;
	errno = STALE_ERRNO;
	return err;
}

static int make_listener(uint_fast16_t *restrict port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	const int enable = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
	struct sockaddr_in bound_addr = { 0 };
	socklen_t len = sizeof(bound_addr);

	T_CHECK(fd >= 0);
	T_CHECK(setsockopt(
			fd, SOL_SOCKET, SO_REUSEADDR, &enable,
			sizeof(enable)) == 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(listen(fd, 1) == 0);
	T_CHECK(fd_set_nonblock(fd));
	T_CHECK(getsockname(fd, (struct sockaddr *)&bound_addr, &len) == 0);
	*port = ntohs(bound_addr.sin_port);
	return fd;
}

static int make_listener6(uint_fast16_t *restrict port)
{
	const int fd = socket(AF_INET6, SOCK_STREAM, 0);
	const int enable = 1;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_loopback,
		.sin6_port = 0,
	};
	struct sockaddr_in6 bound_addr = { 0 };
	socklen_t len = sizeof(bound_addr);

	T_CHECK(fd >= 0);
	T_CHECK(setsockopt(
			fd, SOL_SOCKET, SO_REUSEADDR, &enable,
			sizeof(enable)) == 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(listen(fd, 1) == 0);
	T_CHECK(fd_set_nonblock(fd));
	T_CHECK(getsockname(fd, (struct sockaddr *)&bound_addr, &len) == 0);
	*port = ntohs(bound_addr.sin6_port);
	return fd;
}

static int accept_nowait(const int listener_fd)
{
	for (;;) {
		const int fd = accept(listener_fd, NULL, NULL);
		if (fd < 0 && errno == EINTR) {
			continue;
		}
		if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return -1;
		}
		return fd;
	}
}

static int wait_for_accept(
	struct ev_loop *loop, const int listener_fd,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	for (;;) {
		const int fd = accept_nowait(listener_fd);
		if (fd >= 0 || watchdog.fired) {
			ev_timer_stop(loop, &w_timeout);
			return fd;
		}
		ev_run(loop, EVRUN_ONCE);
	}
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

static bool write_all(const int fd, const void *restrict buf, size_t len)
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

/* Write a proxy reply and the tunnel bytes behind it in a single write, so
 * the dialer's first peek at the reply already sees them queued. */
static bool write_reply(
	const int fd, const void *restrict rsp, const size_t rsp_len,
	const unsigned char *restrict payload, const size_t payload_len)
{
	static unsigned char buf[DIALER_RBUF_SIZE * 3];
	if (rsp_len > sizeof(buf) || payload_len > sizeof(buf) - rsp_len) {
		return false;
	}
	memcpy(buf, rsp, rsp_len);
	if (payload_len > 0) {
		memcpy(buf + rsp_len, payload, payload_len);
	}
	return write_all(fd, buf, rsp_len + payload_len);
}

/* Fill buf with a position-dependent pattern, covering every byte value --
 * NUL, CR and LF included -- so a dropped or shifted byte cannot go unseen. */
static void fill_payload(unsigned char *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)(i * 7 + i / 256);
	}
}

/* Read what a dial left on its fd: up to `want` bytes, waiting for them, then
 * whatever else is already queued, so a caller sees extra bytes as a count
 * above `want`. Returns the count, or -1 on error or timeout. */
static ssize_t recv_tunnel(
	const int fd, unsigned char *restrict buf, const size_t cap,
	const size_t want)
{
	size_t n = 0;
	while (n < want) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		const int ret = poll(&pfd, 1, T_TIMEOUT_SECONDS * 1000);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (ret != 1) {
			return -1;
		}
		const ssize_t r = recv_nowait(fd, buf + n, cap - n);
		if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			continue;
		}
		if (r <= 0) {
			return -1;
		}
		n += (size_t)r;
	}
	if (n < cap) {
		const ssize_t r = recv_nowait(fd, buf + n, cap - n);
		if (r > 0) {
			n += (size_t)r;
		} else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
			return -1;
		}
	}
	return (ssize_t)n;
}

static bool proxy_server_pump(void *data)
{
	struct proxy_server *const server = data;

	if (server->peer_fd < 0) {
		server->peer_fd = accept_nowait(server->listener_fd);
		if (server->peer_fd < 0) {
			return true;
		}
	}
	if (!server->request_complete) {
		const size_t avail =
			sizeof(server->request) - server->request_len - 1;
		const ssize_t n = recv_nowait(
			server->peer_fd, server->request + server->request_len,
			avail);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return true;
			}
			server->failed = true;
			return false;
		}
		if (n == 0) {
			server->failed = true;
			return false;
		}
		server->request_len += (size_t)n;
		server->request[server->request_len] = '\0';
		if (server->request_len + 1 >= sizeof(server->request)) {
			server->failed = true;
			return false;
		}
		if (strstr(server->request, "\r\n\r\n") != NULL) {
			server->request_complete = true;
		}
	}
	if (server->request_complete && !server->response_sent) {
		const size_t total = strlen(server->response);
		const size_t chunk = server->response_chunk != 0 ?
					     server->response_chunk :
					     total;
		size_t n = chunk;
		if (server->response_off + n > total) {
			n = total - server->response_off;
		}
		const bool last = server->response_off + n >= total;
		if (n > 0 &&
		    !write_reply(
			    server->peer_fd,
			    server->response + server->response_off, n,
			    server->payload, last ? server->payload_len : 0)) {
			server->failed = true;
			return false;
		}
		server->response_off += n;
		if (server->response_off >= total) {
			server->response_sent = true;
		}
	}
	return true;
}

/* TEST_WAIT_SEC widened to cover a trickled response.
 *
 * proxy_server_pump() writes at most response_chunk bytes per
 * test_wait_until() iteration, and an iteration costs at least one loopback
 * wake-up of the dialer, so a small chunk over a long response costs far more
 * wall clock than the byte count suggests -- tens of milliseconds for a
 * byte-at-a-time reply, and more on a loaded machine. A case that trickles its
 * reply therefore scales its watchdog with the trickle instead of racing it.
 * The per-round allowance is deliberately far above the measured cost:
 * overshooting only delays a genuinely stuck dial's failure, while
 * undershooting fails a healthy one. */
static ev_tstamp proxy_server_wait_sec(const struct proxy_server *server)
{
	enum { ROUND_ALLOWANCE_MS = 20 };
	const size_t total = strlen(server->response);
	const size_t chunk =
		server->response_chunk != 0 ? server->response_chunk : total;
	const size_t rounds = chunk != 0 ? (total + chunk - 1) / chunk : 1;
	return TEST_WAIT_SEC +
	       (ev_tstamp)rounds * ((ev_tstamp)ROUND_ALLOWANCE_MS * 1e-3);
}

/* Log capture. The sink matters: only the terminal and stream sinks render a
 * struct slog_extra, so text written there is invisible to the writer sink --
 * which the syslog sink matches. The default here is the stream sink, where the
 * peer-supplied text of the message sites lands; the prefix cases below run
 * through both. */
enum logcap_sink {
	LOGCAP_STREAM,
	LOGCAP_WRITER,
};

static struct {
	char buf[8192];
	size_t len;
	struct io_stream *stream;
} g_logcap;

static void logcap_write(void *ud, const unsigned char *buf, size_t len)
{
	(void)ud;
	const size_t space = sizeof(g_logcap.buf) - 1 - g_logcap.len;
	if (len > space) {
		len = space;
	}
	memcpy(g_logcap.buf + g_logcap.len, buf, len);
	g_logcap.len += len;
	g_logcap.buf[g_logcap.len] = '\0';
}

static void logcap_start_sink(const int level, const enum logcap_sink sink)
{
	g_logcap.len = 0;
	g_logcap.buf[0] = '\0';
	g_logcap.stream = NULL;
	if (sink == LOGCAP_STREAM) {
		g_logcap.stream = io_memwriter(
			g_logcap.buf, sizeof(g_logcap.buf) - 1, &g_logcap.len);
		T_CHECK(g_logcap.stream != NULL);
		slog_setoutput(SLOG_OUTPUT_STREAM, g_logcap.stream);
	} else {
		slog_setoutput(SLOG_OUTPUT_WRITER, logcap_write, NULL);
	}
	slog_setlevel(level);
}

static void logcap_start(const int level)
{
	logcap_start_sink(level, LOGCAP_STREAM);
}

/* Restore the default silence, so a case that longjmps out of an assertion
 * cannot leave a sink installed for the next one. */
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

/* True when every captured line was begun by slog itself: one it composed
 * starts with its level letter, a space and the timestamp, and a struct
 * slog_extra continuation is indented. A line matching neither was started by
 * bytes that reached the line verbatim -- a forged entry. */
static bool logcap_lines_wellformed(void)
{
	for (const char *line = g_logcap.buf; *line != '\0';) {
		const char *const eol = strchr(line, '\n');
		const size_t linelen =
			(eol != NULL) ? (size_t)(eol - line) : strlen(line);
		if (linelen > 0 && *line != ' ') {
			if (line[0] < 'A' || 'Z' < line[0] || line[1] != ' ' ||
			    line[2] < '0' || '9' < line[2]) {
				return false;
			}
		}
		if (eol == NULL) {
			break;
		}
		line = eol + 1;
	}
	return true;
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

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - address/request parsing and CONNECT handshakes against raw
 * loopback peers.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(dialaddr_parse_and_format_variants)
{
	struct dialaddr addr = { 0 };
	char buf[128];

	T_EXPECT(dialaddr_parse(&addr, "127.0.0.1:1080", 14));
	T_EXPECT_EQ(addr.type, ATYP_INET);
	T_EXPECT_EQ(addr.port, UINT16_C(1080));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 14);
	T_EXPECT_STREQ(buf, "127.0.0.1:1080");

	T_EXPECT(dialaddr_parse(&addr, "[::1]:5353", 10));
	T_EXPECT_EQ(addr.type, ATYP_INET6);
	T_EXPECT_EQ(addr.port, UINT16_C(5353));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 10);
	T_EXPECT_STREQ(buf, "[::1]:5353");

	T_EXPECT(dialaddr_parse(&addr, "example.com:443", 15));
	T_EXPECT_EQ(addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(addr.port, UINT16_C(443));
	T_EXPECT_EQ(addr.domain.len, strlen("example.com"));
	T_EXPECT_MEMEQ(addr.domain.name, "example.com", addr.domain.len);
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 15);
	T_EXPECT_STREQ(buf, "example.com:443");

	T_EXPECT(!dialaddr_parse(&addr, "missing-port", 12));
	T_EXPECT(!dialaddr_parse(&addr, "127.0.0.1:70000", 15));

	/* strtoumax() would skip leading whitespace and accept a sign; a port is
	 * *DIGIT (RFC 3986), so a non-digit-leading port must be rejected even
	 * though it reaches client-controlled input via the CONNECT authority */
	T_EXPECT(!dialaddr_parse(&addr, "example.com:+443", 16));
	T_EXPECT(!dialaddr_parse(&addr, "example.com:-0", 14));
	T_EXPECT(!dialaddr_parse(&addr, "example.com: 443", 16));
}

T_DECLARE_CASE(dialaddr_parse_rejects_embedded_nul)
{
	static const struct {
		const char *text;
		size_t len;
	} bad[] = {
		{ "example.com:443\0.attacker",
		  CONSTSTRLEN("example.com:443\0.attacker") },
		{ "127.0.0.1:1080\0.attacker",
		  CONSTSTRLEN("127.0.0.1:1080\0.attacker") },
		{ "[::1]:443\0.attacker", CONSTSTRLEN("[::1]:443\0.attacker") },
		{ "example.com:443", sizeof("example.com:443") },
	};
	struct dialaddr addr = { 0 };
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		T_EXPECT(!dialaddr_parse(&addr, bad[i].text, bad[i].len));
	}
	/* Bytes beyond the supplied length do not belong to the address. */
	T_EXPECT(dialaddr_parse(
		&addr, bad[0].text, CONSTSTRLEN("example.com:443")));
	T_EXPECT_EQ(addr.port, UINT16_C(443));
	static const char exact[] = { 'a', ':', '8', '0' };
	T_EXPECT(dialaddr_parse(&addr, exact, sizeof(exact)));
	T_EXPECT_EQ(addr.domain.len, 1);
}

T_DECLARE_CASE(dialreq_addproxy_rejects_embedded_nul)
{
	static const struct {
		const char *text;
		size_t len;
	} bad[] = {
		{ "http://127.0.0.1:8080\0.attacker",
		  CONSTSTRLEN("http://127.0.0.1:8080\0.attacker") },
		{ "socks5://user:pass@127.0.0.1:1080\0tail",
		  CONSTSTRLEN("socks5://user:pass@127.0.0.1:1080\0tail") },
		{ "http://example.com\0:8080",
		  CONSTSTRLEN("http://example.com\0:8080") },
		{ "socks4a://example.com:1080",
		  sizeof("socks4a://example.com:1080") },
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		struct dialreq *const req = dialreq_new(NULL, 1);
		T_CHECK(req != NULL);
		const bool accepted =
			dialreq_addproxy(req, bad[i].text, bad[i].len);
		const size_t count = req->num_proxy;
		dialreq_free(req);
		T_EXPECT(!accepted);
		T_EXPECT_EQ(count, (size_t)0);
	}
	struct dialreq *const req = dialreq_new(NULL, 1);
	T_CHECK(req != NULL);
	T_EXPECT(dialreq_addproxy(
		req, bad[0].text, CONSTSTRLEN("http://127.0.0.1:8080")));
	T_EXPECT_EQ(req->num_proxy, (size_t)1);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(8080));
	dialreq_free(req);
}

T_DECLARE_SUBCASE(expect_bad_address, const char *restrict s)
{
	struct dialaddr addr = { 0 };
	if (dialaddr_parse(&addr, s, strlen(s))) {
		T_FATALF("accepted an invalid address: `%s'", s);
	}
}

/*
 * RFC 3986 3.2.2 spells the bracketed host form as
 * IP-literal = "[" ( IPv6address / IPvFuture ) "]", and a reg-name may hold no
 * bracket at all: the brackets exist only to keep an IPv6 literal's colons
 * apart from the "host:port" separator. Stripping them and handing whatever was
 * inside to the IPv4/domain fallbacks accepted authorities that name nothing
 * dialable -- an RFC 6874 zone id resolved as the literal domain "fe80::1%eth0"
 * -- and mis-spelled ones that do, so a bracketed host must parse as an IPv6
 * address or be refused. The same split also let an empty host through.
 */
T_DECLARE_CASE(dialaddr_parse_rejects_invalid_authority)
{
	static const char *const bad[] = {
		/* bracketed, but not an IPv6 literal */
		"[example.com]:80",
		"[127.0.0.1]:80",
		"[v1.fe80::1]:80",
		/* RFC 6874 zone id: no IPv6 literal inet_pton() accepts */
		"[fe80::1%25eth0]:80",
		"[fe80::1%eth0]:80",
		/* malformed brackets */
		"[]:80",
		"[::1:80",
		"[::1]x:80",
		/* no host at all */
		":80",
		/* no port at all */
		"[::1]",
		"example.com",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		T_CALL_SUBCASE(expect_bad_address, bad[i]);
	}

	/* the bracketed forms that remain valid */
	struct dialaddr addr = { 0 };
	char buf[64];
	T_EXPECT(dialaddr_parse(&addr, "[::1]:5353", 10));
	T_EXPECT_EQ(addr.type, ATYP_INET6);
	T_EXPECT(dialaddr_parse(&addr, "[::ffff:127.0.0.1]:9", 20));
	T_EXPECT_EQ(addr.type, ATYP_INET6);
	T_EXPECT(dialaddr_parse(&addr, "[2001:db8::1]:443", 17));
	T_EXPECT_EQ(addr.type, ATYP_INET6);
	T_EXPECT(dialaddr_format(buf, sizeof(buf), &addr) > 0);
	T_EXPECT_STREQ(buf, "[2001:db8::1]:443");
}

/*
 * A name reaches dialaddr_parse() from a ruleset result and from an HTTP proxy
 * request-target, and is written back out into a CONNECT request-line and its
 * Host field, which RFC 9112 3 frames on the space and the CRLF. A host name
 * spells neither: RFC 1035 2.3.1 with RFC 1123 2.1 build one from ASCII
 * letters, digits and hyphens, and RFC 5891 5 dials a non-ASCII name as its
 * ASCII A-label.
 */
T_DECLARE_CASE(dialaddr_parse_rejects_a_name_no_request_can_carry)
{
	static const char *const bad[] = {
		/* what frames the request line and its fields */
		"evil.example\r\nX-Injected yes:80",
		"evil.example\r:80",
		"evil.example\n:80",
		"evil example:80",
		"evil\texample:80",
		/* the remaining bytes no request-target may spell */
		"evil\x01.example:80",
		"evil\x7f.example:80",
		"evil\xc3\xa9.example:80",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		T_CALL_SUBCASE(expect_bad_address, bad[i]);
	}

	/* a printable name still parses, punycode and underscores included */
	static const char *const good[] = {
		"example.com:443",
		"xn--fsqu00a.example:443",
		"_svc._tcp.example.com:80",
		"a-b.example:1",
	};
	struct dialaddr addr = { 0 };
	for (size_t i = 0; i < ARRAY_SIZE(good); i++) {
		if (!dialaddr_parse(&addr, good[i], strlen(good[i]))) {
			T_FATALF("refused a valid address: `%s'", good[i]);
		}
		T_EXPECT_EQ(addr.type, ATYP_DOMAIN);
	}
}

/*
 * The same invariant's other end. A host name is one or more labels and a label
 * one or more characters (RFC 1035 2.3.1, RFC 1123 2.1), so the empty string
 * names nothing: written into a CONNECT it leaves the request-target and the
 * Host field without the host RFC 9110 9.3.6 requires them to carry. No parse
 * entry mints one, and the length check stops there -- the shortest name parses.
 */
T_DECLARE_CASE(dialaddr_parse_rejects_an_empty_name)
{
	T_CALL_SUBCASE(expect_bad_address, ":80");
	T_CALL_SUBCASE(expect_bad_address, ":0");

	struct dialaddr addr = { 0 };
	T_EXPECT(dialaddr_parse(&addr, "a:80", CONSTSTRLEN("a:80")));
	T_EXPECT_EQ(addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(addr.domain.len, 1);
}

/*
 * An address names a destination to dial and carries no scheme to take a
 * default port from, so its port subcomponent has to be there and has to name
 * a port. strtoumax() reads the empty string as 0 with no trailing byte, and
 * split_authority() reported a trailing colon as a port rather than as none,
 * so `example.com:' parsed as port 0 -- and so did the `:0' a peer may spell
 * outright, which RFC 6335 6 reserves and no TCP connection reaches. An HTTP
 * proxy request-target is one of these addresses (RFC 9110 9.3.6), so both
 * were dialled instead of refused with 400.
 */
T_DECLARE_CASE(dialaddr_parse_requires_a_port_a_connection_reaches)
{
	static const char *const bad[] = {
		/* an empty port subcomponent */
		"example.com:",
		"127.0.0.1:",
		"[::1]:",
		/* the reserved port, spelled out */
		"example.com:0",
		"127.0.0.1:0",
		"[::1]:0",
		"example.com:00000",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		T_CALL_SUBCASE(expect_bad_address, bad[i]);
	}

	/* the lowest port a connection reaches still parses */
	struct dialaddr addr = { 0 };
	T_EXPECT(dialaddr_parse(&addr, "example.com:1", 13));
	T_EXPECT_EQ(addr.port, UINT16_C(1));
}

T_DECLARE_CASE(format_max_length_domain_fits_buffers)
{
	/* The longest dialaddr is a max-length (FQDN_MAX_LENGTH) domain with a
	 * 5-digit port: it must format to exactly DIALADDR_STRLEN, and as a
	 * socks4a proxy to exactly PROXYREQ_STRLEN. Every formatted-address log
	 * buffer is now sized from these constants, so pin them to the real
	 * maxima to guard the off-by-one that undersized proxy[]/status_str[]. */
	char domain[FQDN_MAX_LENGTH + 1];
	memset(domain, 'a', FQDN_MAX_LENGTH);
	domain[FQDN_MAX_LENGTH] = '\0';

	struct dialaddr addr = { 0 };
	addr.type = ATYP_DOMAIN;
	addr.port = UINT16_C(65535);
	addr.domain.len = (uint_least8_t)FQDN_MAX_LENGTH;
	memcpy(addr.domain.name, domain, FQDN_MAX_LENGTH);

	char abuf[DIALADDR_STRLEN + 1];
	T_EXPECT_EQ(
		dialaddr_format(abuf, sizeof(abuf), &addr),
		(int)DIALADDR_STRLEN);
	T_EXPECT_EQ(strlen(abuf), DIALADDR_STRLEN);
	T_EXPECT_STREQ(abuf + FQDN_MAX_LENGTH, ":65535");

	char proxy_uri[512];
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://%s:65535",
			domain) > 0);
	struct dialreq *req = dialreq_parse("127.0.0.1:80", proxy_uri);
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, (size_t)1);

	char pbuf[512];
	T_EXPECT(dialreq_format(pbuf, sizeof(pbuf), req) > 0);
	const char *arrow = strstr(pbuf, "->");
	T_CHECK(arrow != NULL);
	/* the proxy URI portion is exactly PROXYREQ_STRLEN, not truncated */
	T_EXPECT_EQ((size_t)(arrow - pbuf), PROXYREQ_STRLEN);
	dialreq_free(req);
}

T_DECLARE_CASE(dialaddr_set_and_copy)
{
	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(UINT16_C(8080)),
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	struct sockaddr_in6 in6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UINT16_C(8443)),
		.sin6_addr = in6addr_loopback,
	};
	struct dialaddr addr = { 0 };
	struct dialaddr copied = { 0 };
	char buf[128];

	T_EXPECT(dialaddr_set(&addr, (const struct sockaddr *)&in, sizeof(in)));
	T_EXPECT_EQ(addr.type, ATYP_INET);
	T_EXPECT_EQ(addr.port, UINT16_C(8080));
	T_EXPECT(dialaddr_set(
		&copied, (const struct sockaddr *)&in6, sizeof(in6)));
	T_EXPECT_EQ(copied.type, ATYP_INET6);
	T_EXPECT_EQ(copied.port, UINT16_C(8443));
	T_EXPECT(!dialaddr_set(
		&copied, (const struct sockaddr *)&in6, sizeof(in6) - 1));

	addr = (struct dialaddr){ 0 };
	addr.type = ATYP_DOMAIN;
	addr.port = UINT16_C(53);
	addr.domain.len = (uint_least8_t)strlen("resolver.local");
	(void)memcpy(addr.domain.name, "resolver.local", addr.domain.len);
	dialaddr_copy(&copied, &addr);
	T_EXPECT_EQ(copied.type, ATYP_DOMAIN);
	T_EXPECT_EQ(copied.port, UINT16_C(53));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &copied), 17);
	T_EXPECT_STREQ(buf, "resolver.local:53");
}

T_DECLARE_CASE(dialreq_parse_and_format_proxy_chain)
{
	struct dialreq *req = dialreq_parse(
		"example.com:443",
		"http://user:pass@127.0.0.1:8080,socks5://127.0.0.2");
	char buf[256];

	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 2);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(8080));
	T_EXPECT_STREQ(req->proxy[0].username, "user");
	T_EXPECT_STREQ(req->proxy[0].password, "pass");
	T_EXPECT_EQ(req->proxy[1].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[1].addr.port, UINT16_C(1080));
	T_EXPECT_EQ(req->proxy[1].username, NULL);
	T_EXPECT_EQ(dialreq_format(buf, sizeof(buf), req), 63);
	T_EXPECT_STREQ(
		buf,
		"http://127.0.0.1:8080->socks5://127.0.0.2:1080->example.com:443");
	dialreq_free(req);
}

/*
 * Regression: `-f :' is the configuration's only spelling for forward mode with
 * no fixed destination -- the shipped usage text and the README's load balancer
 * both use it -- and the daemon refused it at startup once every address had to
 * carry a host. dialreq_parse() is the configuration's own entry point, so the
 * placeholder stops there: dialaddr_parse(), which an HTTP CONNECT target and a
 * ruleset result reach, still refuses a host-less authority.
 */
T_DECLARE_CASE(dialreq_parse_accepts_the_forward_placeholder)
{
	char buf[64];
	struct dialreq *req = dialreq_parse(CONF_FORWARD_ANY, NULL);
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 0);
	T_EXPECT_EQ(req->addr.type, ATYP_INET);
	T_EXPECT_EQ(req->addr.port, UINT16_C(0));
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "0.0.0.0:0");
	dialreq_free(req);

	/* the wildcard a missing address makes, spelled out */
	req = dialreq_parse(NULL, NULL);
	T_CHECK(req != NULL);
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "0.0.0.0:0");
	dialreq_free(req);

	/* the `-x' hops in front of it are still parsed */
	req = dialreq_parse(CONF_FORWARD_ANY, "socks5://127.0.0.1:1080");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 1);
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "socks5://127.0.0.1:1080->0.0.0.0:0");
	dialreq_free(req);

	/* no address a peer supplies spells the placeholder */
	T_CALL_SUBCASE(expect_bad_address, CONF_FORWARD_ANY);
	T_CALL_SUBCASE(expect_bad_address, ":0");
	T_CALL_SUBCASE(expect_bad_address, ":80");
}

T_DECLARE_CASE(dialreq_parse_scheme_default_ports)
{
	/* http defaults to port 80, socks4a/socks5 to 1080 when omitted. */
	struct dialreq *req =
		dialreq_parse("example.com:443", "http://127.0.0.1");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 1);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(80));
	dialreq_free(req);

	req = dialreq_parse("example.com:443", "socks4a://127.0.0.1");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS4A);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(1080));
	dialreq_free(req);
}

/*
 * The same default, reached the other way. RFC 3986 3.2.3 spells a URI's port
 * as *DIGIT and has a normalizer drop an empty one, and RFC 9110 4.2.1 reads
 * an empty port as the scheme's default just like an absent one -- so
 * `http://host:' names port 80. The fallback ran only when the authority
 * carried no colon at all, so a trailing colon named port 0 and every request
 * over that proxy failed to connect. An explicit `:0' is not a default: it
 * names the port RFC 6335 6 reserves, and the URI is refused.
 */
T_DECLARE_CASE(dialreq_parse_empty_proxy_port_is_the_scheme_default)
{
	char buf[128];
	struct dialreq *req =
		dialreq_parse("example.com:443", "http://127.0.0.1:");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, (size_t)1);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(80));
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "http://127.0.0.1:80->example.com:443");
	dialreq_free(req);

	req = dialreq_parse("example.com:443", "socks4a://127.0.0.1:");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS4A);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(1080));
	dialreq_free(req);

	/* the bracketed authority splits its port the same way */
	req = dialreq_parse("example.com:443", "socks5://[::1]:");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET6);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(1080));
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "socks5://[::1]:1080->example.com:443");
	dialreq_free(req);
}

/*
 * splithostport() writes a NUL at the last ':' before it decides an unbracketed
 * multi-colon host is invalid, so the caller's "no port, use the scheme
 * default" fallback must not read the string back after a failed split -- it
 * has already been truncated ("[::1]" to "[:", "::1" to ":"). A bracketed IPv6
 * authority with no port is RFC 3986-valid and must reach the default port as
 * the address it names.
 */
T_DECLARE_CASE(dialreq_parse_bracketed_ipv6_proxy_authority)
{
	struct dialreq *req =
		dialreq_parse("example.com:443", "socks5://[::1]");
	char buf[128];

	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, (size_t)1);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET6);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(1080));
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "socks5://[::1]:1080->example.com:443");
	dialreq_free(req);

	req = dialreq_parse("example.com:443", "http://[::1]");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET6);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(80));
	dialreq_free(req);

	req = dialreq_parse("example.com:443", "socks5://[2001:db8::1]:9999");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET6);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(9999));
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "socks5://[2001:db8::1]:9999->example.com:443");
	dialreq_free(req);
}

/*
 * The same fallback also accepted authorities that name no usable host at all:
 * an unbracketed IPv6 literal (ambiguous with "host:port"), an empty authority,
 * and an empty host before a port.
 */
T_DECLARE_SUBCASE(expect_bad_proxy_uri, const char *restrict uri)
{
	struct dialreq *const req = dialreq_parse("example.com:443", uri);
	if (req != NULL) {
		dialreq_free(req);
		T_FATALF("accepted an invalid proxy uri: `%s'", uri);
	}
}

T_DECLARE_CASE(dialreq_parse_rejects_ambiguous_proxy_authority)
{
	static const char *const uris[] = {
		"socks5://::1",	 "socks5://::1:9999", "socks5://2001:db8::1",
		"http://",	 "socks5://:1080",    "socks5://[]",
		"socks5://[::1", "socks5://[::1]x",   "socks5://[::1]9999",
	};
	for (size_t i = 0; i < ARRAY_SIZE(uris); i++) {
		T_CALL_SUBCASE(expect_bad_proxy_uri, uris[i]);
	}
}

/* The bracket rule reaches the proxy chain through its own authority split:
 * a bracketed proxy host must be an IPv6 literal there too, with or without a
 * port, whichever scheme names it. */
T_DECLARE_CASE(dialreq_parse_rejects_bracketed_non_ipv6_proxy_authority)
{
	static const char *const uris[] = {
		"socks5://[example.com]",     "socks5://[example.com]:1080",
		"http://[127.0.0.1]:8080",    "socks4a://[127.0.0.1]",
		"socks5://[v1.fe80::1]:1080", "socks5://[fe80::1%25eth0]",
	};
	for (size_t i = 0; i < ARRAY_SIZE(uris); i++) {
		T_CALL_SUBCASE(expect_bad_proxy_uri, uris[i]);
	}
}

T_DECLARE_CASE(dialreq_parse_rejects_bad_proxy_uris)
{
	/* unknown scheme */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "ftp://127.0.0.1:21"), NULL);
	/* missing scheme / unparseable */
	T_EXPECT_EQ(dialreq_parse("example.com:443", "127.0.0.1:1080"), NULL);
	/* the reserved port, which no default ever names (RFC 6335 6) */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "http://127.0.0.1:0"), NULL);
	T_EXPECT_EQ(dialreq_parse("example.com:443", "socks5://[::1]:0"), NULL);
	/* port out of range */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "http://127.0.0.1:99999"),
		NULL);
	/* non-numeric port */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "http://127.0.0.1:abc"), NULL);
}

T_DECLARE_CASE(dialreq_parse_rejects_overlong_proxy_uri)
{
	char uri[1100];
	const int n = snprintf(uri, sizeof(uri), "socks5://");
	memset(uri + n, 'a', sizeof(uri) - 1 - (size_t)n);
	uri[sizeof(uri) - 1] = '\0';
	T_EXPECT_EQ(dialreq_parse("example.com:443", uri), NULL);
}

/*
 * The "proxy chain too long" guard exists to bound the proxy[] allocation
 * dialreq_parse() sizes from the comma count, so it has to run before that
 * allocation -- an over-long chain reached it only after ~800 bytes per comma
 * had already been requested. The result is NULL either way; what this pins is
 * the size the parse asks for.
 */
T_DECLARE_CASE(dialreq_parse_bounds_chain_before_allocating)
{
	const size_t len = (size_t)UINT16_MAX + 1;
	char *const csv = malloc(len + 1);
	T_CHECK(csv != NULL);
	memset(csv, ',', len);
	csv[len] = '\0';

	g_malloc_peak = 0;
	g_malloc_track = true;
	struct dialreq *const req = dialreq_parse("example.com:443", csv);
	g_malloc_track = false;
	const size_t peak = g_malloc_peak;
	free(csv);
	dialreq_free(req);

	T_EXPECT_EQ(req, NULL);
	T_EXPECT(peak < sizeof(struct proxyreq) * 256);
}

/*
 * dialreq_addproxy() appends at req->num_proxy with no bound of its own, so an
 * append past what dialreq_new() reserved wrote a whole proxyreq off the end of
 * the allocation. The request carries its own capacity instead of trusting the
 * caller's bookkeeping.
 */
T_DECLARE_CASE(dialreq_addproxy_rejects_a_full_chain)
{
	static const char uri[] = "socks5://127.0.0.1:1080";
	struct dialreq *const req = dialreq_new(NULL, 1);

	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, (size_t)0);
	T_EXPECT(dialreq_addproxy(req, uri, strlen(uri)));
	T_EXPECT_EQ(req->num_proxy, (size_t)1);
	T_EXPECT(!dialreq_addproxy(req, uri, strlen(uri)));
	T_EXPECT_EQ(req->num_proxy, (size_t)1);
	dialreq_free(req);
}

/*
 * proxy_copy() runs proxy_set_credential() into a proxyreq straight out of
 * malloc(), so dropping its failure leaves username/password pointing at
 * uninitialized heap -- which send_http_req() then dereferences. A base whose
 * credential strings do not fit must fail the copy instead.
 */
T_DECLARE_CASE(dialreq_new_rejects_an_oversized_credential)
{
	char cred[300];
	memset(cred, 'c', sizeof(cred) - 1);
	cred[sizeof(cred) - 1] = '\0';

	struct dialreq *const base =
		malloc(sizeof(struct dialreq) + sizeof(struct proxyreq));
	T_CHECK(base != NULL);
	base->addr = (struct dialaddr){
		.type = ATYP_INET,
		.port = UINT16_C(443),
		.in = { htonl(INADDR_LOOPBACK) },
	};
	base->num_proxy = 1;
	base->proxy[0].proto = PROTO_SOCKS5;
	dialaddr_copy(&base->proxy[0].addr, &base->addr);
	base->proxy[0].username = cred;
	base->proxy[0].password = cred;

	struct dialreq *const copy = dialreq_new(base, 0);
	T_EXPECT_EQ(copy, NULL);
	dialreq_free(copy);
	free(base);
}

/*
 * The boundary the copy above relies on: a credential filling proxyreq's buffer
 * exactly still round-trips through dialreq_new(), and the first byte past it
 * is refused while the proxy URI is parsed -- before any proxyreq exists.
 */
T_DECLARE_CASE(dialreq_copies_a_max_length_credential)
{
	char user[256], pass[256], uri[768];
	memset(user, 'u', sizeof(user) - 1);
	user[sizeof(user) - 1] = '\0';
	memset(pass, 'p', sizeof(pass) - 1);
	pass[sizeof(pass) - 1] = '\0';

	/* strlen(user) + 1 + strlen(pass) + 1 == sizeof(proxyreq.credential) */
	T_CHECK(snprintf(
			uri, sizeof(uri), "socks5://%s:%s@127.0.0.1:1080", user,
			pass) > 0);
	struct dialreq *const base = dialreq_parse("example.com:443", uri);
	T_CHECK(base != NULL);
	struct dialreq *const copy = dialreq_new(base, 0);
	T_CHECK(copy != NULL);
	T_EXPECT_EQ(copy->num_proxy, (size_t)1);
	T_EXPECT_STREQ(copy->proxy[0].username, user);
	T_EXPECT_STREQ(copy->proxy[0].password, pass);
	dialreq_free(copy);
	dialreq_free(base);

	T_CHECK(snprintf(
			uri, sizeof(uri), "socks5://%sx:%s@127.0.0.1:1080",
			user, pass) > 0);
	T_EXPECT_EQ(dialreq_parse("example.com:443", uri), NULL);
}

T_DECLARE_CASE(dialreq_replace_swaps_on_success)
{
	struct dialreq *req = dialreq_parse("example.com:443", NULL);
	T_CHECK(req != NULL);

	T_EXPECT(dialreq_replace(&req, "example.org:80", NULL));
	T_CHECK(req != NULL);
	char buf[64];
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "example.org:80");

	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_replace_keeps_old_on_failure)
{
	struct dialreq *req = dialreq_parse("example.com:443", NULL);
	T_CHECK(req != NULL);
	struct dialreq *const original = req;

	/* unknown scheme: dialreq_parse fails, so req must be left untouched */
	T_EXPECT(!dialreq_replace(
		&req, "example.com:443", "ftp://127.0.0.1:21"));
	T_EXPECT_EQ(req, original);
	char buf[64];
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "example.com:443");

	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_new_copies_base_request)
{
	struct dialreq *base = dialreq_parse(
		"example.com:443", "socks5://alice:secret@127.0.0.1");
	struct dialreq *copy;
	char buf[256];

	T_CHECK(base != NULL);
	copy = dialreq_new(base, 1);
	T_CHECK(copy != NULL);
	T_EXPECT_EQ(copy->num_proxy, 1);
	T_EXPECT_EQ(copy->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_STREQ(copy->proxy[0].username, "alice");
	T_EXPECT_STREQ(copy->proxy[0].password, "secret");
	T_EXPECT_EQ(copy->proxy[0].addr.port, UINT16_C(1080));
	T_EXPECT_EQ(dialreq_format(buf, sizeof(buf), copy), 40);
	T_EXPECT_STREQ(buf, "socks5://127.0.0.1:1080->example.com:443");
	dialreq_free(copy);
	dialreq_free(base);
}

T_DECLARE_CASE(dialer_strerror_known_and_unknown)
{
	T_EXPECT_STREQ(dialer_strerror(DIALER_OK), "success");
	T_EXPECT_STREQ(
		dialer_strerror(DIALER_ERR_PROXY_AUTH),
		"proxy authentication failed");
	T_EXPECT_STREQ(
		dialer_strerror((enum dialer_error)DIALER_ERR_MAX),
		"unknown error");
	/* A code from below the table is as out of bounds as one from above it,
	 * and dialer_strerror() bounds both ends by comparing as unsigned. Such
	 * a code reaches it as raw storage -- corrupted, or minted by another
	 * build -- so build it that way rather than by naming a value the type
	 * has no enumerator for. */
	union {
		int raw;
		enum dialer_error err;
	} foreign = { .raw = -1 };
	T_EXPECT_STREQ(dialer_strerror(foreign.err), "unknown error");
}

T_DECLARE_CASE(direct_connect_reports_success)
{
	uint_fast16_t port = 0;
	const int listener_fd = make_listener(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(addr, sizeof(addr), "127.0.0.1:%u", (unsigned)port) >
		0);
	req = dialreq_parse(addr, NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	int accepted_fd = wait_for_accept(loop, listener_fd, TEST_WAIT_SEC);
	int client_fd = result.fd;
	const bool accepted = accepted_fd >= 0;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	T_CHECK(close(listener_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT(has_client_fd);
	T_EXPECT(accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(local_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("10.0.0.1:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_local = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression: an IPv4-mapped IPv6 literal (::ffff:a.b.c.d) must be classified
 * by its embedded IPv4 address so the egress policy catches it, rather than
 * sailing past block_local/block_loopback/block_multicast as IPCLASS_GLOBAL --
 * which would defeat the policy for anyone reaching it via a SOCKS5 ATYP_INET6
 * request (or a TPROXY dual-stack listener).
 */
T_DECLARE_CASE(v4_mapped_local_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("[::ffff:10.0.0.1]:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_local = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Same gap, different flag: an IPv4-mapped loopback literal must be caught
 * by block_loopback specifically (not just block_local).
 */
T_DECLARE_CASE(v4_mapped_loopback_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("[::ffff:127.0.0.1]:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_loopback = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression: after the csnippets sync added IPCLASS_SHARED, a 100.64.0.0/10
 * (RFC 6598 CGNAT) target fell through to the "invalid" default and was refused
 * with DIALER_ERR_BLOCKED regardless of policy. Under the default config it
 * must instead pass the egress check and be dialed, as it was before the sync
 * (when it classified IPCLASS_GLOBAL). The connect() interposer forces a
 * synchronous refusal so the test observes "reached connect (not blocked)"
 * without any real network traffic.
 */
T_DECLARE_CASE(shared_cgnat_address_is_dialable_by_default)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("100.64.0.1:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	g_force_connect_fail = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	g_force_connect_fail = false;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	/* not blocked: it passed check_outbound_sa and reached the forced
	 * connect() failure */
	T_EXPECT_EQ(err, DIALER_ERR_CONNECT);
}

/*
 * struct dialer documents syserr as carrying the OS error for DIALER_ERR_CONNECT
 * as well as DIALER_ERR_SYSTEM, and dialer_errorstr() appends it whenever it is
 * set. Pin that premise on the most common failure the dialer produces: a
 * refused connect must arrive with its errno, not a bare DIALER_ERR_CONNECT.
 */
T_DECLARE_CASE(connect_failure_reports_errno)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("203.0.113.1:9", NULL);
	char buf[128];

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	g_force_connect_fail = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	const char *const errstr = dialer_errorstr(buf, sizeof(buf), &d);
	g_force_connect_fail = false;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_CONNECT);
	T_EXPECT_EQ(syserr, ECONNREFUSED);
	/* the errno was appended, so the scratch buffer was used */
	T_EXPECT_EQ(errstr, buf);
	T_EXPECT(strstr(buf, "connection failed") == buf);
}

/*
 * A failed socket setup must report the errno the setter returned. Reading the
 * global errno instead recovers a plausible value only while the setters are
 * implemented over fcntl(); their contract leaves it undefined, and the dial
 * would then blame an unrelated error.
 */
T_DECLARE_SUBCASE(socket_setup_failure_case, int *const arm, const int want)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("203.0.113.1:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	*arm = want;
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	const int armed = *arm;
	*arm = 0;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	/* the armed failure was consumed, so the dial is what tripped it */
	T_EXPECT_EQ(armed, 0);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_SYSTEM);
	T_EXPECT_EQ(syserr, want);
}

T_DECLARE_CASE(socket_setup_failure_reports_setter_errno)
{
	T_CALL_SUBCASE(
		socket_setup_failure_case, &g_cloexec_fail_errno, EMFILE);
	T_CALL_SUBCASE(
		socket_setup_failure_case, &g_nonblock_fail_errno, ENFILE);
}

/*
 * The reserved-for-future-use block (240.0.0.0/4, RFC 1112), another class the
 * csnippets sync introduced, is non-routable and must be refused outright --
 * with its own case, not the ERROR-level "invalid" default.
 */
T_DECLARE_CASE(reserved_address_blocked_by_egress_policy)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("240.0.0.1:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_success_sends_expected_request)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"http://user:pass@127.0.0.1:%u", (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_STREQ(
		server.request,
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Host: example.com:443\r\n"
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* The name a peer sends and the request it smuggles with it. */
#define SMUGGLE_NAME                                                           \
	"evil.example\r\nX-Injected: yes\r\n\r\n"                              \
	"GET /admin HTTP/1.1\r\nHost: internal"

/* Where the peer's name sits in the request. */
enum name_site {
	/* the destination, as socks.c fills it from DST.ADDR */
	NAME_AT_TARGET,
	/* the hop a preceding HTTP proxy is told to CONNECT to */
	NAME_AT_HOP,
};

/* Fill an address the way a front end does: socks.c writes a struct dialaddr
 * straight from the wire, so these bytes never pass dialaddr_parse(). */
static void set_domain(
	struct dialaddr *restrict addr, const char *restrict name,
	const size_t len, const uint_fast16_t port)
{
	T_CHECK(len <= FQDN_MAX_LENGTH);
	addr->type = ATYP_DOMAIN;
	addr->port = (uint_least16_t)port;
	addr->domain.len = (uint_least8_t)len;
	memcpy(addr->domain.name, name, len);
}

T_DECLARE_SUBCASE(
	expect_nothing_reaches_the_proxy, const char *restrict name,
	const size_t namelen, const uint_fast16_t port_num,
	const enum name_site site)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_new(NULL, 2);
	T_CHECK(req != NULL);
	T_CHECK(dialreq_addproxy(req, proxy_uri, strlen(proxy_uri)));
	if (site == NAME_AT_HOP) {
		static const char next[] = "socks5://198.51.100.1:1080";
		T_CHECK(dialreq_addproxy(req, next, sizeof(next) - 1));
		set_domain(
			&req->addr, "example.com", CONSTSTRLEN("example.com"),
			443);
		set_domain(&req->proxy[1].addr, name, namelen, port_num);
	} else {
		set_domain(&req->addr, name, namelen, port_num);
	}
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	/* the exact bytes the upstream proxy read, none being the verdict */
	if (server.request_len > 0) {
		T_FATALF("the proxy received: %s", server.request);
	}
	T_EXPECT(!server.request_complete);
	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BADADDR);
	T_EXPECT_EQ(syserr, 0);
}

/*
 * The destination reaches the dialer as the bytes the client wrote: a SOCKS5
 * DOMAINNAME is length-prefixed with no character set of its own (RFC 1928, 5),
 * socks.c keeps it verbatim so the ruleset decides on the name as sent, and
 * send_http_req() then splices it into the CONNECT request-line and the Host
 * field. A CRLF in it ends the request line there, so the peer writes header
 * fields of its own and, past a bare CRLFCRLF, a whole second request the proxy
 * reads on the same connection (CWE-93/CWE-444). The dial is refused before the
 * connection is made, so no byte of the name reaches the proxy -- and the same
 * holds for a chain hop, which a preceding HTTP proxy is told to CONNECT to.
 */
T_DECLARE_CASE(dial_refuses_a_name_no_request_can_carry)
{
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, SMUGGLE_NAME,
		CONSTSTRLEN(SMUGGLE_NAME), 80, NAME_AT_TARGET);
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, SMUGGLE_NAME,
		CONSTSTRLEN(SMUGGLE_NAME), 80, NAME_AT_HOP);
}

/*
 * The degenerate case of the same invariant. RFC 1928 5 length-prefixes
 * DST.ADDR, so a DOMAINNAME of length zero is well-formed on the wire and
 * socks5_req() fills a struct dialaddr with it; socks4a_req() reaches the same
 * state from a name that is only its null terminator. Rendered into a CONNECT
 * it leaves the request-target and the Host field with no host at all, and a
 * SOCKS4a or SOCKS5 hop is handed a name of no bytes -- so the dial is refused
 * before the connection is made, at the destination and at a chain hop alike.
 */
T_DECLARE_CASE(dial_refuses_an_empty_name)
{
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, "", (size_t)0, 80,
		NAME_AT_TARGET);
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, "", (size_t)0, 80,
		NAME_AT_HOP);
}

/*
 * The address's other half. dialaddr_parse() refuses a port no connection
 * reaches, but socks.c fills a struct dialaddr straight from the wire: RFC
 * 1928 5 gives DST.PORT two bytes and no minimum, so a client may request the
 * port RFC 6335 6 reserves. connect() cannot name it, and an HTTP hop would be
 * told to CONNECT there, so the dial is refused before the connection is made
 * -- at the destination and at a chain hop alike.
 */
T_DECLARE_CASE(dial_refuses_a_port_no_connection_reaches)
{
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, "example.com",
		CONSTSTRLEN("example.com"), 0, NAME_AT_TARGET);
	T_CALL_SUBCASE(
		expect_nothing_reaches_the_proxy, "example.com",
		CONSTSTRLEN("example.com"), 0, NAME_AT_HOP);
}

/*
 * The scheme default, as the bytes a peer reads. A test cannot bind port 80 to
 * observe the hop the daemon connects to, but the hop *after* it is observable:
 * a preceding HTTP proxy renders it into the CONNECT request-line and the Host
 * field, so a chain whose second hop is written with a trailing colon says
 * which port the daemon resolved it to.
 */
T_DECLARE_SUBCASE(
	expect_hop_authority, const char *restrict hop_uri,
	const char *restrict expect_request)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 403 Forbidden\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	char csv[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			csv, sizeof(csv), "http://127.0.0.1:%u,%s",
			(unsigned)port, hop_uri) > 0);
	struct dialreq *const req = dialreq_parse("example.com:443", csv);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	/* the exact bytes the first hop read */
	T_EXPECT_STREQ(server.request, expect_request);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
}

T_DECLARE_CASE(dial_over_an_empty_proxy_port_uses_the_scheme_default)
{
	T_CALL_SUBCASE(
		expect_hop_authority, "http://127.0.0.1:",
		"CONNECT 127.0.0.1:80 HTTP/1.1\r\n"
		"Host: 127.0.0.1:80\r\n\r\n");
	T_CALL_SUBCASE(
		expect_hop_authority, "socks4a://127.0.0.1:",
		"CONNECT 127.0.0.1:1080 HTTP/1.1\r\n"
		"Host: 127.0.0.1:1080\r\n\r\n");
	T_CALL_SUBCASE(
		expect_hop_authority, "socks5://127.0.0.1:",
		"CONNECT 127.0.0.1:1080 HTTP/1.1\r\n"
		"Host: 127.0.0.1:1080\r\n\r\n");
}

/*
 * A synchronous connect() success (connect() returns 0, not EINPROGRESS) into a
 * proxied dial takes connect_sa()'s num_proxy>0 branch: STATE_HANDSHAKE1 with
 * send_dispatch() sending the first handshake inline. Real loopback sockets
 * always report EINPROGRESS, so this branch is otherwise never exercised; force
 * it with the connect() interposer above and confirm the handshake completes.
 */
T_DECLARE_CASE(sync_connect_success_into_http_handshake)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);

	g_sync_connect_ret = -2;
	g_force_sync_connect = true;
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	g_force_sync_connect = false;

	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	/* connect() returned 0, so connect_sa() took the synchronous branch. */
	T_EXPECT_EQ(g_sync_connect_ret, 0);
	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_STREQ(
		server.request, "CONNECT example.com:443 HTTP/1.1\r\n"
				"Host: example.com:443\r\n\r\n");
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression: a proxy reply delivered one byte at a time (as a slow/adversarial
 * upstream hop might) must still be parsed correctly. dialer_recv() peeks
 * (MSG_PEEK) rather than consumes, and re-peeking before the next consume
 * re-reads bytes already counted in rbuf.len; before the fix each re-peek
 * accumulated onto the previous length (triangular growth: len after k one-byte
 * fragments ~= k*(k+1)/2). That inflated length drives the SO_RCVLOWAT wakeup
 * target past the bytes the reply will ever contain -- so the dialer stalls
 * waiting for more -- and, once it reaches DIALER_RBUF_SIZE, additionally trips
 * "response too long" (PROXY_PROTO); either way an ordinary reply fails. This
 * asserts a byte-at-a-time reply still completes, independent of buffer size.
 */
T_DECLARE_CASE(http_connect_success_with_byte_at_a_time_response)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established for "
			    "upstream target\r\n\r\n",
		.response_chunk = 1,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* The dialer reached the final response's header block, or ended first. */
static bool dialer_hdr_block_predicate(void *data)
{
	const struct dialer *const d = data;
	return d->state == DIALER_STATE_HANDSHAKE2 ||
	       d->state == DIALER_STATE_DONE;
}

/*
 * Regression: when a CONNECT response's status line and header-block
 * terminator arrive in separate segments, consuming the status line drains the
 * socket queue, and recv_http_hdr() then asks consume_rcvbuf() for zero bytes.
 * That zero-length recv() fails with EAGAIN on a drained non-blocking socket,
 * which was reported as DIALER_ERR_SYSTEM -- failing a dial whose reply was
 * merely incomplete. The split follows the dialer's own state, not timing.
 */
T_DECLARE_CASE(http_connect_split_response_reports_success)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	/* status line only; the terminating CRLF is written below */
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool consumed_status = test_wait_until(
		loop, dialer_hdr_block_predicate, &d,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const bool ended_on_status_line = result.called;
	if (!ended_on_status_line) {
		T_CHECK(write_all(server.peer_fd, "\r\n", 2));
	}
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	int client_fd = result.fd;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(consumed_status);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT(completed);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(syserr, 0);
	T_EXPECT(has_client_fd);
	/* an incomplete header block is not an outcome */
	T_EXPECT(!ended_on_status_line);
}

/*
 * Regression (#70): the receive buffer was sized from request maxima, capping an
 * upstream proxy's CONNECT response at ~1 KiB, so a conforming proxy sending a
 * larger header block (Via/X-Cache stacks, a long auth challenge, portal
 * Set-Cookie) had its otherwise-successful 200 misreported as "response too
 * long" (PROXY_PROTO). A valid 200 padded well past the old 1032-byte bound must
 * now be accepted.
 */
T_DECLARE_CASE(http_connect_success_with_large_response_headers)
{
	/* one header value long enough to push the whole response past the old
	 * 1032-byte cap while staying within DIALER_RBUF_SIZE */
	char filler[1500];
	memset(filler, 'a', sizeof(filler) - 1);
	filler[sizeof(filler) - 1] = '\0';
	char response[2048];
	const int rn = snprintf(
		response, sizeof(response),
		"HTTP/1.1 200 Connection Established\r\n"
		"X-Padding: %s\r\n\r\n",
		filler);
	T_CHECK(rn > 1032 && (size_t)rn < sizeof(response));

	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = response,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression (#126): a single header line larger than the peek slack, delivered
 * fragmented, must still complete. dialer_recv() sized its MSG_PEEK window from
 * rbuf.len -- which counts the peeked-but-unconsumed fragment -- so once that
 * fragment exceeded the remaining slack the window could never hold the whole
 * line, rbuf.len oscillated, and SO_RCVLOWAT re-fired EV_READ into a 100%-CPU
 * busy loop. A >4 KiB header line that fits DIALER_RBUF_SIZE, delivered in
 * chunks, must be accepted (the window is now sized from the consumed offset).
 */
T_DECLARE_CASE(http_connect_success_with_fragmented_large_header_line)
{
	/* a single header line well over 4 KiB but within DIALER_RBUF_SIZE */
	char filler[5000];
	memset(filler, 'a', sizeof(filler) - 1);
	filler[sizeof(filler) - 1] = '\0';
	char response[6144];
	const int rn = snprintf(
		response, sizeof(response),
		"HTTP/1.1 200 Connection Established\r\n"
		"X-Long: %s\r\n\r\n",
		filler);
	T_CHECK(rn > 4096 && (size_t)rn < sizeof(response));

	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = response,
		/* chunk the reply so the status line is consumed and a large
		 * partial header line remains peeked -- the livelock trigger */
		.response_chunk = 4096,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_407_maps_to_proxy_auth)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response =
			"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_AUTH);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_403_maps_to_proxy_reject)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 403 Forbidden\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_502_maps_to_proxy_refused)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 502 Bad Gateway\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_non_200_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 500 Internal Server Error\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression (#127): a 200 response followed by a malformed header line (no
 * colon) must fail the dial with an error. recv_http_hdr()'s http_parsehdr()
 * failure branch returned -1 without setting d->err, so the dial aborted while
 * still reporting DIALER_OK -- and socks.c then relayed SOCKS5RSP_SUCCEEDED to
 * the client for a connection that was already dead.
 */
T_DECLARE_CASE(http_connect_malformed_header_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 OK\r\nBadHeaderNoColon\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&result.fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	/* the dial must fail, not report success with a dead connection */
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
	T_EXPECT_EQ(d.syserr, 0);
}

/* recv_http_rsp() rejects any response whose version is not HTTP/1.x; the
 * version check runs before the status-code check, so a 200 with an
 * unsupported version must still map to DIALER_ERR_PROXY_PROTO. */
T_DECLARE_CASE(http_connect_unsupported_version_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/0.9 200 OK\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive one HTTP CONNECT dial against a mock proxy replying with `response`,
 * delivered `chunk` bytes per pump round (0 sends it whole), and check the
 * outcome the dialer reports. */
T_DECLARE_SUBCASE(
	expect_http_dial, const char *restrict response, const size_t chunk,
	const enum dialer_error expect_err)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = response,
		.response_chunk = chunk,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(err, expect_err);
	T_EXPECT_EQ(syserr, 0);
	T_EXPECT(has_client_fd == (expect_err == DIALER_OK));
}

/*
 * RFC 9112 2.3: HTTP-version = HTTP-name "/" DIGIT "." DIGIT, exactly. A 2xx
 * whose version merely starts with "HTTP/1." is not an HTTP/1.x reply, so it
 * must not start the tunnel.
 */
T_DECLARE_CASE(http_connect_malformed_version_maps_to_proxy_proto)
{
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1. 200 OK\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1x 200 OK\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.10 200 OK\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.0 200 OK\r\n\r\n", 0, DIALER_OK);
}

/*
 * RFC 9110 9.3.6: any 2xx reply to CONNECT switches the connection to tunnel
 * mode. Matching the status against the literal "200" failed an RFC-legal 201
 * or 204 with DIALER_ERR_PROXY_PROTO, which socks.c then relayed as a general
 * server failure.
 */
T_DECLARE_CASE(http_connect_2xx_reports_success)
{
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 201 Created\r\n\r\n", 0, DIALER_OK);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 204 No Content\r\n\r\n", 0,
		DIALER_OK);
	T_CALL_SUBCASE(
		expect_http_dial,
		"HTTP/1.1 299 Tunnelled\r\nVia: 1.1 proxy\r\n\r\n", 0,
		DIALER_OK);
}

/*
 * RFC 9110 15.2: a client must be able to parse one or more 1xx interim
 * responses ahead of the final one, even when it expects none. Each interim
 * response is skipped whole -- status line plus its own header block -- and the
 * next status line parsed as a status line.
 */
T_DECLARE_CASE(http_connect_interim_1xx_reports_success)
{
	T_CALL_SUBCASE(
		expect_http_dial,
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 200 Connection Established\r\n\r\n",
		0, DIALER_OK);
	T_CALL_SUBCASE(
		expect_http_dial,
		"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n"
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 200 Connection Established\r\nVia: 1.1 p\r\n\r\n",
		0, DIALER_OK);
	/* an interim response that arrives split across reads must not be
	 * consumed until its header block is complete */
	T_CALL_SUBCASE(
		expect_http_dial,
		"HTTP/1.1 100 Continue\r\nX-Hint: 1\r\n\r\n"
		"HTTP/1.1 200 Connection Established\r\n\r\n",
		1, DIALER_OK);
	/* a 1xx followed by a failing final response still maps to that
	 * response, not to a protocol error */
	T_CALL_SUBCASE(
		expect_http_dial,
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
		0, DIALER_ERR_PROXY_AUTH);
}

/* RFC 9112 4: the status code is exactly 3DIGIT, and its leading digit names
 * the status class -- anything else is a malformed status line. */
T_DECLARE_CASE(http_connect_invalid_status_code_maps_to_proxy_proto)
{
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 2xx Weird\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 099 Nope\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 2000 Nope\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 20 Nope\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
	/* the neighbouring error classes the change left alone */
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 403 Forbidden\r\n\r\n", 0,
		DIALER_ERR_PROXY_REJECT);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 503 Unavailable\r\n\r\n", 0,
		DIALER_ERR_PROXY_REFUSED);
	T_CALL_SUBCASE(
		expect_http_dial, "HTTP/1.1 302 Found\r\n\r\n", 0,
		DIALER_ERR_PROXY_PROTO);
}

/*
 * DIALER_RBUF_SIZE bounds the CONNECT response header block the dialer will
 * hold, and recv_http_rsp() NUL-terminates the peeked bytes in place: a proxy
 * whose header block fills the buffer must fail the dial rather than have the
 * terminator written one past the end. The large-header cases above stay under
 * the cap (2048 and 6144 bytes); this one crosses it.
 */
T_DECLARE_CASE(http_connect_oversized_response_maps_to_proxy_proto)
{
	char response[DIALER_RBUF_SIZE + 1024];
	const int n = snprintf(
		response, sizeof(response),
		"HTTP/1.1 200 Connection Established\r\nX-Long: ");
	T_CHECK(n > 0 && (size_t)n < sizeof(response));
	/* an unterminated header block: nothing completes it within the cap */
	memset(response + n, 'a', sizeof(response) - 1 - (size_t)n);
	response[sizeof(response) - 1] = '\0';
	T_CHECK(strlen(response) > DIALER_RBUF_SIZE);

	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_ERR_PROXY_PROTO);
}

/* Build a CONNECT response of exactly `len` bytes: a 200 status line and one
 * padding field, terminated by the blank line when `complete` is set, or cut
 * off mid-value otherwise. */
static bool make_http_response(
	char *restrict buf, const size_t cap, const size_t len,
	const bool complete)
{
	static const char head[] = "HTTP/1.1 200 Connection Established\r\n"
				   "X-Pad: ";
	static const char tail[] = "\r\n\r\n";
	const size_t head_len = sizeof(head) - 1;
	const size_t tail_len = complete ? sizeof(tail) - 1 : 0;
	if (len < head_len + tail_len || len >= cap) {
		return false;
	}
	memcpy(buf, head, head_len);
	memset(buf + head_len, 'a', len - head_len - tail_len);
	memcpy(buf + len - tail_len, tail, tail_len);
	buf[len] = '\0';
	return true;
}

/* Drive an HTTP CONNECT dial whose reply is followed, in the same write, by
 * `payload_len` tunnel bytes, and check that the dial succeeds and leaves
 * exactly those bytes on the returned fd. */
T_DECLARE_SUBCASE(
	expect_http_tunnel, const char *restrict response,
	const size_t payload_len)
{
	static unsigned char payload[DIALER_RBUF_SIZE * 2];
	static unsigned char got[sizeof(payload) + 1];
	T_CHECK(payload_len <= sizeof(payload));
	fill_payload(payload, payload_len);
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = response,
		.payload = payload,
		.payload_len = payload_len,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result,
		proxy_server_wait_sec(&server), proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	const ssize_t n =
		client_fd >= 0 ?
			recv_tunnel(client_fd, got, sizeof(got), payload_len) :
			-1;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(n, (ssize_t)payload_len);
	T_EXPECT_MEMEQ(got, payload, payload_len);
}

/*
 * The dialer peeks at a proxy's reply and takes off the socket only the bytes
 * the parser accepts, so whatever follows the final response -- the tunnel's
 * first bytes, sent by a server-first destination as soon as the tunnel opens
 * -- stays queued for the caller to relay.
 */
T_DECLARE_CASE(http_connect_leaves_tunnel_bytes_on_the_socket)
{
	T_CALL_SUBCASE(
		expect_http_tunnel,
		"HTTP/1.1 200 Connection Established\r\n\r\n", 64);
	T_CALL_SUBCASE(
		expect_http_tunnel,
		"HTTP/1.1 100 Continue\r\nX-Hint: 1\r\n\r\n"
		"HTTP/1.1 200 Connection Established\r\nVia: 1.1 p\r\n\r\n",
		64);
	/* a peek returns whatever is queued, so the response and the payload
	 * behind it together fill the receive buffer: that says nothing about
	 * the header block's length, which ended long before */
	T_CALL_SUBCASE(
		expect_http_tunnel, "HTTP/1.1 200 OK\r\n\r\n",
		DIALER_RBUF_SIZE + 1024);
	T_CALL_SUBCASE(
		expect_http_tunnel,
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 200 Connection Established\r\nVia: 1.1 p\r\n\r\n",
		DIALER_RBUF_SIZE + 1024);
}

/*
 * The header block may take the whole receive buffer less the byte the parser
 * NUL-terminates it with. At that size a complete block succeeds, with tunnel
 * bytes queued behind it or not; an unterminated one fails the dial at once
 * rather than waiting for a byte count no peek can return; a complete block
 * one byte longer is over the limit.
 */
T_DECLARE_CASE(http_connect_header_block_at_the_buffer_limit)
{
	static char response[DIALER_RBUF_SIZE + 1];
	const size_t limit = DIALER_RBUF_SIZE - 1;

	T_CHECK(make_http_response(response, sizeof(response), limit, true));
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_OK);
	T_CALL_SUBCASE(expect_http_tunnel, response, 64);
	T_CHECK(make_http_response(response, sizeof(response), limit, false));
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_ERR_PROXY_PROTO);
	T_CHECK(make_http_response(response, sizeof(response), limit + 1, true));
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_ERR_PROXY_PROTO);
}

/* Interim responses reclaim their own headers; the combined exchange may
 * exceed one receive window while each response stays below its limit. */
T_DECLARE_CASE(http_connect_large_interim_responses_reclaim_buffer)
{
	static const char head[] = "HTTP/1.1 103 Early Hints\r\nX-Pad: ";
	static const char tail[] = "\r\n\r\n";
	static char response[2 * DIALER_RBUF_SIZE];
	const size_t padding = 6000;
	const size_t interim_len =
		sizeof(head) - 1 + padding + sizeof(tail) - 1;
	memcpy(response, head, sizeof(head) - 1);
	memset(response + sizeof(head) - 1, 'a', padding);
	memcpy(response + sizeof(head) - 1 + padding, tail, sizeof(tail) - 1);
	T_CHECK(make_http_response(
		response + interim_len, sizeof(response) - interim_len, 3000,
		true));
	T_CHECK(interim_len < DIALER_RBUF_SIZE &&
		strlen(response) > DIALER_RBUF_SIZE);
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_OK);
	T_CALL_SUBCASE(expect_http_dial, response, 127, DIALER_OK);
	T_CALL_SUBCASE(expect_http_tunnel, response, DIALER_RBUF_SIZE + 64);

	/* Reclaiming the prefix must not admit an oversized final block. */
	T_CHECK(make_http_response(
		response + interim_len, sizeof(response) - interim_len,
		DIALER_RBUF_SIZE, true));
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_ERR_PROXY_PROTO);
}

T_DECLARE_CASE(http_connect_many_interim_responses_reclaim_buffer)
{
	static const char interim[] = "HTTP/1.1 100 Continue\r\n\r\n";
	static const char final[] = "HTTP/1.1 200 OK\r\n\r\n";
	static char response[2 * DIALER_RBUF_SIZE];
	const size_t count = DIALER_RBUF_SIZE / (sizeof(interim) - 1) + 2;
	size_t len = 0;
	for (size_t i = 0; i < count; i++) {
		memcpy(response + len, interim, sizeof(interim) - 1);
		len += sizeof(interim) - 1;
	}
	memcpy(response + len, final, sizeof(final));
	T_CHECK(strlen(response) > DIALER_RBUF_SIZE);
	T_CALL_SUBCASE(expect_http_dial, response, 0, DIALER_OK);
	/* Each fragment is one whole interim, leaving an empty suffix when it
	 * is consumed before the final status line is delivered. */
	T_CALL_SUBCASE(
		expect_http_dial, response, sizeof(interim) - 1, DIALER_OK);
	T_CALL_SUBCASE(expect_http_tunnel, response, 64);
}

struct socks4_raw_server {
	int listener_fd;
	int peer_fd;
	unsigned char buf[512];
	size_t buf_len;
	bool request_complete;
	bool response_sent;
	bool failed;
	uint_least8_t rsp_code;
	/* tunnel bytes sent in the same write as the reply (default none) */
	const unsigned char *payload;
	size_t payload_len;
};

/* Returns true when a complete SOCKS4/4a request has been accumulated. */
static bool
socks4_request_complete(const unsigned char *restrict buf, const size_t len)
{
	const unsigned char *userid_end;

	if (len <= SOCKS4_HDR_LEN) {
		return false;
	}
	userid_end = memchr(buf + SOCKS4_HDR_LEN, '\0', len - SOCKS4_HDR_LEN);
	if (userid_end == NULL) {
		return false;
	}
	/* SOCKS4a: header IP 0.0.0.x (x != 0) means a domain name follows. */
	if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0) {
		const unsigned char *const host_start = userid_end + 1;
		const size_t host_space =
			len - SOCKS4_HDR_LEN -
			(size_t)(host_start - (buf + SOCKS4_HDR_LEN));
		return memchr(host_start, '\0', host_space) != NULL;
	}
	return true;
}

static bool socks4_raw_pump(void *data)
{
	struct socks4_raw_server *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	if (!s->request_complete) {
		const ssize_t n = recv_nowait(
			s->peer_fd, s->buf + s->buf_len,
			sizeof(s->buf) - s->buf_len);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				s->failed = true;
				return false;
			}
		} else if (n == 0) {
			s->failed = true;
			return false;
		} else {
			s->buf_len += (size_t)n;
		}
		if (socks4_request_complete(s->buf, s->buf_len)) {
			s->request_complete = true;
		}
	}
	if (s->request_complete && !s->response_sent) {
		const unsigned char rsp[SOCKS4_HDR_LEN] = {
			0, s->rsp_code, 0, 0, 0, 0, 0, 0,
		};
		if (!write_reply(
			    s->peer_fd, rsp, sizeof(rsp), s->payload,
			    s->payload_len)) {
			s->failed = true;
			return false;
		}
		s->response_sent = true;
	}
	return true;
}

T_DECLARE_CASE(socks4a_rejected_maps_to_proxy_refused)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_REJECTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive a SOCKS4a dial against a mock proxy answering with `rsp_code`, and
 * check the dialer error it maps to. */
T_DECLARE_SUBCASE(
	expect_socks4a_failure, const uint_least8_t rsp_code,
	const enum dialer_error expect_err)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = rsp_code,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	const int client_fd = result.fd;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(client_fd, -1);
	T_EXPECT_EQ(err, expect_err);
	T_EXPECT_EQ(syserr, 0);
}

/*
 * SOCKS4 CD 92 and 93 are well-formed rejections (the server could not reach
 * the client's identd, and an identd user-id mismatch), not malformed
 * responses: classifying them as DIALER_ERR_PROXY_PROTO cost the accurate
 * SOCKS5RSP_NOALLOWED relay and the "rejected by proxy" description.
 */
T_DECLARE_CASE(socks4a_identd_failures_map_to_reject_and_auth)
{
	T_CALL_SUBCASE(
		expect_socks4a_failure, SOCKS4RSP_NOIDENTD,
		DIALER_ERR_PROXY_REJECT);
	T_CALL_SUBCASE(
		expect_socks4a_failure, SOCKS4RSP_IDENTMISMATCH,
		DIALER_ERR_PROXY_AUTH);
	/* the neighbouring codes keep their existing classification */
	T_CALL_SUBCASE(
		expect_socks4a_failure, UINT8_C(91), DIALER_ERR_PROXY_REFUSED);
	T_CALL_SUBCASE(
		expect_socks4a_failure, UINT8_C(94), DIALER_ERR_PROXY_PROTO);
}

T_DECLARE_CASE(socks4a_granted_reports_success)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_GRANTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* A SOCKS4a GRANTED reply is 8 bytes; the tunnel bytes the proxy relays in
 * the same write stay on the socket for the caller. */
T_DECLARE_CASE(socks4a_granted_leaves_tunnel_bytes_on_the_socket)
{
	unsigned char payload[64];
	unsigned char got[sizeof(payload) + 1];
	fill_payload(payload, sizeof(payload));
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_GRANTED,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	const ssize_t n = client_fd >= 0 ? recv_tunnel(
						   client_fd, got, sizeof(got),
						   sizeof(payload)) :
					   -1;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(n, (ssize_t)sizeof(payload));
	T_EXPECT_MEMEQ(got, payload, sizeof(payload));
}

/* #178: the proxy credential's username is sent as the SOCKS4a userid, between
 * the 8-byte fixed header and the target hostname. */
T_DECLARE_CASE(socks4a_sends_userid)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_GRANTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks4a://alice@127.0.0.1:%u", (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	unsigned char reqbuf[512];
	const size_t buf_len = server.buf_len < sizeof(reqbuf) ?
				       server.buf_len :
				       sizeof(reqbuf);
	memcpy(reqbuf, server.buf, buf_len);
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	/* userid "alice\0" follows the 8-byte SOCKS4 header */
	T_EXPECT(buf_len >= SOCKS4_HDR_LEN + 6);
	T_EXPECT_MEMEQ(reqbuf + SOCKS4_HDR_LEN, "alice", 6);
}

/* send_socks4a_req() encodes an IPv6-literal target as a SOCKS4a hostname (the
 * ATYP_INET6 branch), which the domain-target cases never exercise: the request
 * must carry the IPv6 address string in the hostname slot after the empty
 * userid. */
T_DECLARE_CASE(socks4a_ipv6_target_encodes_hostname)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_GRANTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("[2001:db8::1]:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks4_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	/* no proxy userid, so the hostname starts right after the empty userid
	 * NUL that follows the 8-byte header */
	const bool host_encoded =
		server.request_complete &&
		strcmp((const char *)server.buf + SOCKS4_HDR_LEN + 1,
		       "2001:db8::1") == 0;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(host_encoded);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

enum socks5_pump_phase {
	SOCKS5_PHASE_AUTH,
	SOCKS5_PHASE_USERPASS,
	SOCKS5_PHASE_CONNECT,
	SOCKS5_PHASE_DONE,
};

struct socks5_raw_server {
	int listener_fd;
	int peer_fd;
	unsigned char buf[512];
	size_t buf_len;
	enum socks5_pump_phase phase;
	bool response_sent;
	bool failed;
	uint_least8_t rsp_code;
	/* reply with a domain-form BND.ADDR instead of the default IPv4 one */
	bool bnd_domain;
	/* auth method offered in the negotiation reply (default 0 == NOAUTH) */
	uint_least8_t auth_method;
	/* additional handshakes to service on the same connection after the
	 * first, for a tunnelled multi-hop proxy chain (default 0) */
	int extra_hops;
	/* the CONNECT request (from the ATYP byte through the port) captured for
	 * the test to assert the encoded request target */
	unsigned char req_target[260];
	size_t req_target_len;
	/* tunnel bytes sent in the same write as the final CONNECT reply
	 * (default none) */
	const unsigned char *payload;
	size_t payload_len;
};

static bool socks5_raw_pump(void *data)
{
	struct socks5_raw_server *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	/* Once the CONNECT response has been sent, the handshake is complete. */
	if (s->phase == SOCKS5_PHASE_DONE) {
		return true;
	}
	const ssize_t n = recv_nowait(
		s->peer_fd, s->buf + s->buf_len, sizeof(s->buf) - s->buf_len);
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			s->failed = true;
			return false;
		}
	} else if (n == 0) {
		if (s->phase != SOCKS5_PHASE_DONE) {
			s->failed = true;
			return false;
		}
	} else {
		s->buf_len += (size_t)n;
	}
	if (s->phase == SOCKS5_PHASE_AUTH) {
		/* Need: version(1) + nmethods(1) + methods(nmethods) */
		if (s->buf_len < 2) {
			return true;
		}
		const size_t auth_len = (size_t)2 + s->buf[1];
		if (s->buf_len < auth_len) {
			return true;
		}
		const unsigned char auth_rsp[2] = { SOCKS5, s->auth_method };
		if (!write_all(s->peer_fd, auth_rsp, sizeof(auth_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= auth_len;
		memmove(s->buf, s->buf + auth_len, s->buf_len);
		s->phase = (s->auth_method == SOCKS5AUTH_USERPASS) ?
				   SOCKS5_PHASE_USERPASS :
				   SOCKS5_PHASE_CONNECT;
	}
	if (s->phase == SOCKS5_PHASE_USERPASS) {
		/* USERPASS sub-negotiation (RFC 1929):
		 * ver(1) ulen(1) uname(ulen) plen(1) passwd(plen) */
		if (s->buf_len < 2) {
			return true;
		}
		const size_t ulen = s->buf[1];
		if (s->buf_len < (size_t)2 + ulen + 1) {
			return true;
		}
		const size_t plen = s->buf[2 + ulen];
		const size_t up_len = (size_t)2 + ulen + 1 + plen;
		if (s->buf_len < up_len) {
			return true;
		}
		/* reply version 0x01, status 0x00 (success) */
		const unsigned char up_rsp[2] = { 0x01, 0x00 };
		if (!write_all(s->peer_fd, up_rsp, sizeof(up_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= up_len;
		memmove(s->buf, s->buf + up_len, s->buf_len);
		s->phase = SOCKS5_PHASE_CONNECT;
	}
	if (s->phase == SOCKS5_PHASE_CONNECT) {
		/* SOCKS5 request: hdr(4) + addr_data + port(2) */
		if (s->buf_len < SOCKS5_HDR_LEN + 1) {
			return true;
		}
		size_t addr_len;
		switch (s->buf[3]) {
		case SOCKS5ADDR_IPV4:
			addr_len = sizeof(struct in_addr);
			break;
		case SOCKS5ADDR_IPV6:
			addr_len = sizeof(struct in6_addr);
			break;
		case SOCKS5ADDR_DOMAIN:
			addr_len = (size_t)1 + s->buf[SOCKS5_HDR_LEN];
			break;
		default:
			s->failed = true;
			return false;
		}
		const size_t req_len =
			SOCKS5_HDR_LEN + addr_len + sizeof(in_port_t);
		if (s->buf_len < req_len) {
			return true;
		}
		/* capture the request target (ATYP..port) for assertion */
		s->req_target_len = addr_len + 1 + sizeof(in_port_t);
		if (s->req_target_len <= sizeof(s->req_target)) {
			memcpy(s->req_target, s->buf + 3, s->req_target_len);
		}
		/* Respond with rsp_code. Default BND.ADDR is 0.0.0.0:0; the
		 * bnd_domain variant replies with a domain-form BND.ADDR. */
		const unsigned char connect_rsp
			[SOCKS5_HDR_LEN + sizeof(struct in_addr) +
			 sizeof(in_port_t)] = {
				SOCKS5, s->rsp_code, 0, SOCKS5ADDR_IPV4,
				0,	0,	     0, 0,
				0,	0,
			};
		const unsigned char domain_rsp[] = {
			SOCKS5, s->rsp_code, 0, SOCKS5ADDR_DOMAIN, 3, 'a', 'b',
			'c',	0,	     0,
		};
		const unsigned char *const rsp =
			s->bnd_domain ? domain_rsp : connect_rsp;
		const size_t rsp_len = s->bnd_domain ? sizeof(domain_rsp) :
						       sizeof(connect_rsp);
		const size_t payload_len =
			s->extra_hops > 0 ? 0 : s->payload_len;
		if (!write_reply(
			    s->peer_fd, rsp, rsp_len, s->payload,
			    payload_len)) {
			s->failed = true;
			return false;
		}
		s->buf_len -= req_len;
		memmove(s->buf, s->buf + req_len, s->buf_len);
		s->response_sent = true;
		if (s->extra_hops > 0) {
			/* the dialer tunnels the next hop's SOCKS5 handshake
			 * over this same connection; negotiate again */
			s->extra_hops--;
			s->phase = SOCKS5_PHASE_AUTH;
		} else {
			s->phase = SOCKS5_PHASE_DONE;
		}
	}
	return true;
}

T_DECLARE_CASE(socks5_noallowed_maps_to_proxy_reject)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_NOALLOWED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_connect_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* #178: dialing an IPv4 target through a SOCKS5 proxy must encode the request
 * target as ATYP_IPV4 + the four address bytes + the big-endian port. */
T_DECLARE_CASE(socks5_connect_ipv4_target_encoding)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("1.2.3.4:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT_EQ(err, DIALER_OK);
	static const unsigned char want[] = {
		SOCKS5ADDR_IPV4, 1, 2, 3, 4, 0x01, 0xBB, /* 443 */
	};
	T_EXPECT_EQ(server.req_target_len, sizeof(want));
	T_EXPECT_MEMEQ(server.req_target, want, sizeof(want));
}

/* #178: dialing an IPv6 target through a SOCKS5 proxy must encode the request
 * target as ATYP_IPV6 + the sixteen address bytes + the big-endian port. */
T_DECLARE_CASE(socks5_connect_ipv6_target_encoding)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("[::1]:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT_EQ(err, DIALER_OK);
	static const unsigned char want[] = {
		SOCKS5ADDR_IPV6,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		1, /* ::1 */
		0x01,
		0xBB, /* 443 */
	};
	T_EXPECT_EQ(server.req_target_len, sizeof(want));
	T_EXPECT_MEMEQ(server.req_target, want, sizeof(want));
}

/* Regression: RFC 1928 permits a domain-form BND.ADDR in a SUCCEEDED reply;
 * recv_socks5_rsp must accept it, not reject the dial as a protocol error. */
T_DECLARE_CASE(socks5_connect_success_domain_bnd_addr)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.bnd_domain = true,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive a SOCKS5 dial whose CONNECT reply carries an IPv4 or a domain-form
 * BND.ADDR, followed in the same write by tunnel bytes, and check that the
 * dialer takes exactly the reply -- its length depends on the address form --
 * and leaves the tunnel bytes on the returned fd. */
T_DECLARE_SUBCASE(expect_socks5_tunnel, const bool bnd_domain)
{
	unsigned char payload[64];
	unsigned char got[sizeof(payload) + 1];
	fill_payload(payload, sizeof(payload));
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.bnd_domain = bnd_domain,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	const ssize_t n = client_fd >= 0 ? recv_tunnel(
						   client_fd, got, sizeof(got),
						   sizeof(payload)) :
					   -1;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(n, (ssize_t)sizeof(payload));
	T_EXPECT_MEMEQ(got, payload, sizeof(payload));
}

T_DECLARE_CASE(socks5_connect_leaves_tunnel_bytes_on_the_socket)
{
	T_CALL_SUBCASE(expect_socks5_tunnel, false);
	T_CALL_SUBCASE(expect_socks5_tunnel, true);
}

/* Regression: an over-255-byte SOCKS5 username must make send_socks5_auth
 * fail with a real error, not leave d.err at DIALER_OK (which socks.c maps to
 * SOCKS5RSP_SUCCEEDED, telling the client a failed dial succeeded). */
T_DECLARE_CASE(socks5_oversized_username_fails)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char longuser[300];
	char proxy_uri[512];

	T_CHECK(loop != NULL);
	memset(longuser, 'a', sizeof(longuser) - 1);
	longuser[sizeof(longuser) - 1] = '\0';
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://%s:p@127.0.0.1:%u", longuser,
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	(void)test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	const bool called = result.called;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT(err != DIALER_OK);
}

/* Live multi-hop: the dialer must advance d->jump and re-run the SOCKS5
 * handshake over the tunnelled connection for each proxy in the chain. */
T_DECLARE_CASE(socks5_chain_two_hops_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.extra_hops = 1,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	/* first hop is the mock; the second hop address is never really dialed
	 * (the mock replies SUCCEEDED for it), it only drives a second
	 * handshake over the same connection */
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://127.0.0.1:%u,socks5://127.0.0.2:1080",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT_EQ(server.extra_hops, 0);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive a full SOCKS5 USERPASS sub-negotiation to success: the mock offers
 * USERPASS, parses the credentials the dialer sends, and replies with a 0x00
 * status. Exercises recv_socks5_auth()'s happy path (version 0x01, status
 * 0x00 -> STATE_HANDSHAKE3), which the NOAUTH cases never reach. */
T_DECLARE_CASE(socks5_userpass_auth_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://user:pass@127.0.0.1:%u", (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Regression: when we have no credentials we advertise only NOAUTH, so a
 * server selecting USERPASS picked a method we never offered. The dialer must
 * reject it as a protocol error rather than dereference the NULL username in
 * send_socks5_auth (a crash in release builds where the ASSERT is compiled
 * out). */
T_DECLARE_CASE(socks5_unoffered_userpass_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	/* no userinfo -> proxy->username == NULL -> only NOAUTH offered */
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	(void)test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	const bool called = result.called;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
}

/* recv_socks5_authmethod() maps a server reply of 0xFF (NO ACCEPTABLE METHODS)
 * to DIALER_ERR_PROXY_AUTH; the other auth-method cases never send 0xFF. */
T_DECLARE_CASE(socks5_no_acceptable_method_maps_to_proxy_auth)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_NOACCEPTABLE,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	(void)test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	const bool called = result.called;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_AUTH);
}

/*
 * A proxy peer that plays a fixed script: each step reads exactly the request
 * the dialer is expected to send, byte for byte, and answers it with a canned
 * reply. The reply is what a case chooses freely -- a bad version, a status or
 * REP code, a BND.ATYP the parsers must refuse -- and the request check pins
 * the bytes the dialer sends on the way there.
 */
struct peer_step {
	const void *request;
	size_t request_len;
	const void *reply;
	size_t reply_len;
};

struct scripted_peer {
	int listener_fd;
	int peer_fd;
	const struct peer_step *steps;
	size_t num_steps;
	size_t step;
	unsigned char buf[512];
	size_t buf_len;
	bool failed;
};

static bool scripted_peer_pump(void *data)
{
	struct scripted_peer *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	if (s->step >= s->num_steps) {
		return true;
	}
	const struct peer_step *const step = &s->steps[s->step];
	/* read no further than this step's request: the dialer sends the next
	 * one only once it has read this reply */
	if (s->buf_len < step->request_len) {
		const ssize_t n = recv_nowait(
			s->peer_fd, s->buf + s->buf_len,
			step->request_len - s->buf_len);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				s->failed = true;
				return false;
			}
			return true;
		}
		if (n == 0) {
			s->failed = true;
			return false;
		}
		s->buf_len += (size_t)n;
		if (s->buf_len < step->request_len) {
			return true;
		}
	}
	if (memcmp(s->buf, step->request, step->request_len) != 0) {
		s->failed = true;
		return false;
	}
	if (!write_all(s->peer_fd, step->reply, step->reply_len)) {
		s->failed = true;
		return false;
	}
	s->buf_len = 0;
	s->step++;
	return true;
}

/* What the dialer sends dialing example.com:443 over each hop kind. */
static const char socks5_greeting_noauth[] = "\x05\x01\x00";
static const char socks5_greeting_userpass[] = "\x05\x02\x00\x02";
static const char socks5_userpass_request[] = "\x01\x04user\x04pass";
static const char socks5_connect_request[] = "\x05\x01\x00\x03\x0b"
					     "example.com"
					     "\x01\xbb";
static const char socks4a_connect_request[] = "\x04\x01\x01\xbb\x00\x00\x00\xff"
					      "\x00"
					      "example.com"
					      "\x00";

/* Dial example.com:443 through the scripted peer at the proxy URI prefix
 * @p scheme (scheme and userinfo, the authority left to fill in), expecting
 * every step to be played and the dial to end in @p expect_err. */
T_DECLARE_SUBCASE(
	expect_scripted_dial, const char *restrict scheme,
	const struct peer_step *restrict steps, const size_t num_steps,
	const enum dialer_error expect_err)
{
	uint_fast16_t port = 0;
	struct scripted_peer peer = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.steps = steps,
		.num_steps = num_steps,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	for (size_t i = 0; i < num_steps; i++) {
		T_CHECK(steps[i].request_len <= sizeof(peer.buf));
	}
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "%s127.0.0.1:%u", scheme,
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		scripted_peer_pump, &peer);
	int client_fd = result.fd;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	close_if_open(&client_fd);
	close_if_open(&peer.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&peer.listener_fd);

	if (peer.step < num_steps &&
	    peer.buf_len == steps[peer.step].request_len) {
		/* the dialer sent something other than the expected request */
		T_EXPECT_MEMEQ(
			peer.buf, steps[peer.step].request,
			steps[peer.step].request_len);
	}
	T_EXPECT(!peer.failed);
	T_EXPECT_EQ(peer.step, num_steps);
	T_EXPECT(completed);
	T_EXPECT(has_client_fd == (expect_err == DIALER_OK));
	T_EXPECT_EQ(err, expect_err);
	T_EXPECT_EQ(syserr, 0);
}

/* The RFC 1929 request carries VER 0x01, then each of the username and the
 * password as a length octet and its bytes; a peer that accepts it lets the
 * dial through. */
T_DECLARE_CASE(socks5_userpass_request_encodes_the_credential)
{
	static const unsigned char method_userpass[] = { SOCKS5,
							 SOCKS5AUTH_USERPASS };
	static const unsigned char status_success[] = { 0x01, 0x00 };
	static const unsigned char connect_success[] = {
		SOCKS5, SOCKS5RSP_SUCCEEDED, 0, SOCKS5ADDR_IPV4, 0, 0, 0, 0, 0,
		0,
	};
	const struct peer_step steps[] = {
		{ socks5_greeting_userpass,
		  sizeof(socks5_greeting_userpass) - 1, method_userpass,
		  sizeof(method_userpass) },
		{ socks5_userpass_request, sizeof(socks5_userpass_request) - 1,
		  status_success, sizeof(status_success) },
		{ socks5_connect_request, sizeof(socks5_connect_request) - 1,
		  connect_success, sizeof(connect_success) },
	};
	T_CALL_SUBCASE(
		expect_scripted_dial, "socks5://user:pass@", steps,
		ARRAY_SIZE(steps), DIALER_OK);
}

/* recv_socks5_auth(): an RFC 1929 reply that is not VER 0x01 with STATUS 0x00
 * is a failed authentication, whichever of the two is off. */
T_DECLARE_CASE(socks5_userpass_failure_maps_to_proxy_auth)
{
	static const unsigned char method_userpass[] = { SOCKS5,
							 SOCKS5AUTH_USERPASS };
	static const unsigned char replies[][2] = {
		{ 0x01, 0x01 }, /* STATUS: failure */
		{ 0x01, 0xff }, /* STATUS: failure */
		{ SOCKS5, 0x00 }, /* VER: the SOCKS version, not RFC 1929's */
	};
	for (size_t i = 0; i < ARRAY_SIZE(replies); i++) {
		const struct peer_step steps[] = {
			{ socks5_greeting_userpass,
			  sizeof(socks5_greeting_userpass) - 1, method_userpass,
			  sizeof(method_userpass) },
			{ socks5_userpass_request,
			  sizeof(socks5_userpass_request) - 1, replies[i],
			  sizeof(replies[i]) },
		};
		T_CALL_SUBCASE(
			expect_scripted_dial, "socks5://user:pass@", steps,
			ARRAY_SIZE(steps), DIALER_ERR_PROXY_AUTH);
	}
}

/* recv_socks5_rsp(): REP 0x05 is the proxy's refusal, and every other failure
 * code -- one the table names or one past it -- is a protocol error, as are a
 * reply with the wrong VER and one with a BND.ATYP no address can have. */
T_DECLARE_CASE(socks5_reply_failures_map_to_dialer_errors)
{
	static const unsigned char method_noauth[] = { SOCKS5,
						       SOCKS5AUTH_NOAUTH };
	static const struct {
		unsigned char reply[10];
		enum dialer_error err;
	} tests[] = {
		{ { SOCKS5, SOCKS5RSP_CONNREFUSED, 0, SOCKS5ADDR_IPV4, 0, 0, 0,
		    0, 0, 0 },
		  DIALER_ERR_PROXY_REFUSED },
		{ { SOCKS5, SOCKS5RSP_FAIL, 0, SOCKS5ADDR_IPV4, 0, 0, 0, 0, 0,
		    0 },
		  DIALER_ERR_PROXY_PROTO },
		{ { SOCKS5, SOCKS5RSP_HOSTUNREACH, 0, SOCKS5ADDR_IPV4, 0, 0, 0,
		    0, 0, 0 },
		  DIALER_ERR_PROXY_PROTO },
		/* past the last code RFC 1928 6 defines */
		{ { SOCKS5, 0x09, 0, SOCKS5ADDR_IPV4, 0, 0, 0, 0, 0, 0 },
		  DIALER_ERR_PROXY_PROTO },
		{ { SOCKS5, 0xff, 0, SOCKS5ADDR_IPV4, 0, 0, 0, 0, 0, 0 },
		  DIALER_ERR_PROXY_PROTO },
		/* VER: a success from anything but SOCKS5 */
		{ { 0x04, SOCKS5RSP_SUCCEEDED, 0, SOCKS5ADDR_IPV4, 0, 0, 0, 0,
		    0, 0 },
		  DIALER_ERR_PROXY_PROTO },
		/* BND.ATYP: 0x02 names no address type */
		{ { SOCKS5, SOCKS5RSP_SUCCEEDED, 0, 0x02, 0, 0, 0, 0, 0, 0 },
		  DIALER_ERR_PROXY_PROTO },
	};
	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const struct peer_step steps[] = {
			{ socks5_greeting_noauth,
			  sizeof(socks5_greeting_noauth) - 1, method_noauth,
			  sizeof(method_noauth) },
			{ socks5_connect_request,
			  sizeof(socks5_connect_request) - 1, tests[i].reply,
			  sizeof(tests[i].reply) },
		};
		T_CALL_SUBCASE(
			expect_scripted_dial, "socks5://", steps,
			ARRAY_SIZE(steps), tests[i].err);
	}
}

/* recv_socks5_authmethod(): a method-selection reply with the wrong VER, or
 * selecting a method the dialer never offers, is a protocol error. */
T_DECLARE_CASE(socks5_method_selection_errors_map_to_proxy_proto)
{
	static const unsigned char replies[][2] = {
		{ 0x04, SOCKS5AUTH_NOAUTH }, /* VER */
		{ SOCKS5, 0x01 }, /* GSSAPI, never offered */
		{ SOCKS5, 0x80 }, /* a private method, never offered */
	};
	for (size_t i = 0; i < ARRAY_SIZE(replies); i++) {
		const struct peer_step steps[] = {
			{ socks5_greeting_noauth,
			  sizeof(socks5_greeting_noauth) - 1, replies[i],
			  sizeof(replies[i]) },
		};
		T_CALL_SUBCASE(
			expect_scripted_dial, "socks5://", steps,
			ARRAY_SIZE(steps), DIALER_ERR_PROXY_PROTO);
	}
}

/* recv_socks4a_rsp(): a reply's VN is 0; any other is a protocol error, even
 * with CD granting the request. */
T_DECLARE_CASE(socks4a_reply_version_maps_to_proxy_proto)
{
	static const unsigned char replies[][SOCKS4_HDR_LEN] = {
		{ SOCKS4, SOCKS4RSP_GRANTED, 0, 0, 0, 0, 0, 0 },
		{ 0xff, SOCKS4RSP_GRANTED, 0, 0, 0, 0, 0, 0 },
	};
	for (size_t i = 0; i < ARRAY_SIZE(replies); i++) {
		const struct peer_step steps[] = {
			{ socks4a_connect_request,
			  sizeof(socks4a_connect_request) - 1, replies[i],
			  sizeof(replies[i]) },
		};
		T_CALL_SUBCASE(
			expect_scripted_dial, "socks4a://", steps,
			ARRAY_SIZE(steps), DIALER_ERR_PROXY_PROTO);
	}
}

/* Regression: a dialer completing a proxied dial leaves jump == num_proxy and
 * a stale dialed_fd. Re-driving it with a second dialer_do() without
 * dialer_init() must reset that per-dial state; otherwise send_dispatch reads
 * proxy[num_proxy] out of bounds. */
T_DECLARE_CASE(socks5_redial_after_success_resets_state)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);

	/* first dial */
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed1 = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd1 = result.fd;
	T_EXPECT(completed1);
	T_EXPECT(!server.failed);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(d.err, DIALER_OK);
	close_if_open(&client_fd1);

	/* reset the mock to service a fresh connection for the second dial */
	close_if_open(&server.peer_fd);
	server.phase = SOCKS5_PHASE_AUTH;
	server.buf_len = 0;
	server.response_sent = false;

	/* second dial reuses the completed dialer without dialer_init() */
	result.called = false;
	result.fd = -1;
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed2 = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	int client_fd2 = result.fd;
	const enum dialer_error err2 = d.err;
	close_if_open(&client_fd2);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed2);
	T_EXPECT(!server.failed);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err2, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* A proxy peer that reads whatever the dialer sends, optionally answers with
 * `reply`, then half-closes: the dialer meets the EOF in the handshake phase
 * that reply leaves it in. */
struct eof_server {
	int listener_fd;
	int peer_fd;
	/* bytes to send before the half-close; NULL sends nothing */
	const unsigned char *reply;
	size_t reply_len;
	bool eof_sent;
	bool failed;
};

static bool eof_server_pump(void *data)
{
	struct eof_server *const s = data;
	unsigned char buf[512];

	if (s->eof_sent) {
		return true;
	}
	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	const ssize_t n = recv_nowait(s->peer_fd, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			s->failed = true;
			return false;
		}
		return true;
	}
	if (n == 0) {
		s->failed = true;
		return false;
	}
	if (s->reply_len > 0 &&
	    !write_all(s->peer_fd, s->reply, s->reply_len)) {
		s->failed = true;
		return false;
	}
	/* half-close only: the dialer's next recv() reports the EOF, and an
	 * unread request left in the queue cannot turn it into a reset */
	if (shutdown(s->peer_fd, SHUT_WR) != 0) {
		s->failed = true;
		return false;
	}
	s->eof_sent = true;
	return true;
}

/*
 * An upstream proxy that closes the connection mid-handshake is among the
 * commonest real failures. dialer_recv()'s zero-length read must fail the dial
 * as DIALER_ERR_EOF -- with no fd handed to the caller -- whichever protocol
 * and phase it lands in.
 */
T_DECLARE_SUBCASE(
	expect_dial_eof, const char *restrict scheme,
	const unsigned char *restrict reply, const size_t reply_len)
{
	uint_fast16_t port = 0;
	struct eof_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.reply = reply,
		.reply_len = reply_len,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "%s://127.0.0.1:%u",
			scheme, (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		eof_server_pump, &server);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	int client_fd = result.fd;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.eof_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_EOF);
	T_EXPECT_EQ(syserr, 0);
}

T_DECLARE_CASE(proxy_eof_mid_handshake_maps_to_eof)
{
	/* HTTP: closed before the CONNECT response status line */
	T_CALL_SUBCASE(expect_dial_eof, "http", NULL, (size_t)0);
	/* SOCKS4A: closed before the reply */
	T_CALL_SUBCASE(expect_dial_eof, "socks4a", NULL, (size_t)0);
	/* SOCKS5: closed after the method selection, before the reply, so the
	 * EOF lands in the third handshake phase rather than the first */
	static const unsigned char method_noauth[] = {
		SOCKS5,
		SOCKS5AUTH_NOAUTH,
	};
	T_CALL_SUBCASE(
		expect_dial_eof, "socks5", method_noauth,
		sizeof(method_noauth));
}

/* Accept the dial and read its SOCKS5 method-selection request without
 * answering it, so the dialer stays parked in the first handshake phase. */
static bool socks5_greeting_pump(void *data)
{
	struct socks5_raw_server *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	const ssize_t n = recv_nowait(
		s->peer_fd, s->buf + s->buf_len, sizeof(s->buf) - s->buf_len);
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			s->failed = true;
			return false;
		}
		return true;
	}
	if (n == 0) {
		s->failed = true;
		return false;
	}
	s->buf_len += (size_t)n;
	return true;
}

/* The whole method-selection request has arrived: ver(1) nmethods(1) methods */
static bool socks5_greeting_received(void *data)
{
	const struct socks5_raw_server *const s = data;
	return s->buf_len >= 2 && s->buf_len >= (size_t)2 + s->buf[1];
}

/* dialer_cancel() while a SOCKS5 handshake is still in flight must stop the
 * dialer, report DIALER_CANCELLED, close the socket it dialed, and never invoke
 * the finish callback.
 *
 * Which cancel path runs depends on the state the dial is in, so the case
 * cannot advance the loop a fixed number of times and hope: the kernel's listen
 * backlog completes the TCP handshake on its own, so a fixed count decides
 * between DIALER_STATE_CONNECT and DIALER_STATE_HANDSHAKE1 by scheduling alone.
 * Wait on an observed condition -- the mock has read the method-selection
 * request, which the dialer sends only after connect() completed -- and pin the
 * state before cancelling.
 */
T_DECLARE_CASE(dialer_cancel_stops_in_flight_dial)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	/* the greeting is never answered, so the handshake cannot complete and
	 * the dialer stays in flight until we cancel it */
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool greeted = test_wait_until(
		loop, socks5_greeting_received, &server, TEST_WAIT_SEC,
		socks5_greeting_pump, &server);
	const enum dialer_state state = d.state;
	const int dialed_fd = d.w_socket.fd;
	const bool called_before_cancel = result.called;

	dialer_cancel(&d, loop);
	const enum dialer_error err = d.err;
	const enum dialer_state state_after = d.state;
	/* the socket the dial had open was closed, not leaked */
	const bool fd_closed = fcntl(dialed_fd, F_GETFD) < 0 && errno == EBADF;

	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(greeted);
	T_EXPECT(!server.failed);
	T_EXPECT_EQ(state, DIALER_STATE_HANDSHAKE1);
	T_EXPECT(dialed_fd >= 0);
	T_EXPECT(!called_before_cancel);
	T_EXPECT(fd_closed);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_CANCELLED);
	T_EXPECT_EQ(state_after, DIALER_STATE_DONE);
}

static void canary_resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *data,
	const union sockaddr_max *addr, const size_t num_addr)
{
	bool *const done = data;
	(void)q, (void)loop, (void)addr, (void)num_addr;
	*done = true;
}

static bool flag_predicate(void *data)
{
	const bool *const flag = data;
	return *flag;
}

/*
 * dialer_cancel() while the name is still being resolved must drop the query:
 * the resolver answers later, and its answer must not reach the cancelled
 * dialer. Both back ends defer a query's completion to the loop, so the dial
 * is in DIALER_STATE_RESOLVE as dialer_do() returns and its answer is not yet
 * delivered. A second query started after the cancel is the canary: once its
 * answer is in, the loop has delivered the cancelled one's too -- had it
 * reached the dialer, the dial would have moved on to connecting.
 */
T_DECLARE_CASE(dialer_cancel_during_resolve_drops_the_query)
{
	struct config conf = test_conf;
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	char target[32];

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	T_CHECK(snprintf(
			target, sizeof(target), "localhost:%u",
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const enum dialer_state state = d.state;
	const bool has_query = d.resolve_query != NULL;

	dialer_cancel(&d, loop);
	const enum dialer_error err = d.err;
	const enum dialer_state state_after = d.state;
	const bool query_dropped = d.resolve_query == NULL;

	bool canary_done = false;
	const struct resolve_query *const canary = resolve_do(
		resolver,
		(struct resolve_cb){
			.func = canary_resolve_cb,
			.data = &canary_done,
		},
		"localhost", NULL, PF_INET);
	T_CHECK(canary != NULL);
	const bool resolved = test_wait_until(
		loop, flag_predicate, &canary_done, TEST_WAIT_SEC, NULL, NULL);
	const enum dialer_state state_final = d.state;
	const enum dialer_error err_final = d.err;

	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT_EQ(state, DIALER_STATE_RESOLVE);
	T_EXPECT(has_query);
	T_EXPECT(resolved);
	/* the cancelled query's answer never reached the dialer */
	T_EXPECT(!result.called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(state_final, DIALER_STATE_DONE);
	T_EXPECT_EQ(err_final, DIALER_CANCELLED);
	T_EXPECT_EQ(err, DIALER_CANCELLED);
	T_EXPECT_EQ(state_after, DIALER_STATE_DONE);
	T_EXPECT(query_dropped);
}

/* Start a dial that dialer_do() already knows has failed -- its finish is fed
 * to the loop, not yet run -- then cancel it before the loop runs: the fed
 * finish must be withdrawn, so running the loop reports nothing. */
T_DECLARE_SUBCASE(
	expect_cancel_withdraws_the_fed_finish,
	const struct config *restrict conf, const struct dialreq *restrict req)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	T_CHECK(loop != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, conf, NULL, NULL);
	const bool fed = ev_is_pending(&d.w_finish);

	dialer_cancel(&d, loop);
	const bool withdrawn = !ev_is_pending(&d.w_finish);
	(void)ev_run(loop, EVRUN_NOWAIT);
	const enum dialer_error err = d.err;
	const enum dialer_state state = d.state;
	ev_loop_destroy(loop);

	T_EXPECT(fed);
	T_EXPECT(withdrawn);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_CANCELLED);
	T_EXPECT_EQ(state, DIALER_STATE_DONE);
}

/* The two ways dialer_do() fails before the loop runs: check_request()
 * refusing the address, and connect_start() finding no address to try. */
T_DECLARE_CASE(dialer_cancel_withdraws_a_fed_finish)
{
	struct dialreq *const req = dialreq_parse("127.0.0.1:9", NULL);
	T_CHECK(req != NULL);

	/* the loopback address, barred by the egress policy */
	struct config conf = test_conf;
	conf.block_loopback = true;
	T_CALL_SUBCASE(expect_cancel_withdraws_the_fed_finish, &conf, req);

	/* port 0, refused as no address a connection reaches */
	req->addr.port = 0;
	T_CALL_SUBCASE(expect_cancel_withdraws_the_fed_finish, &test_conf, req);

	dialreq_free(req);
}

T_DECLARE_CASE(direct_connect_ipv6_reports_success)
{
	uint_fast16_t port = 0;
	const int listener_fd = make_listener6(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(addr, sizeof(addr), "[::1]:%u", (unsigned)port) > 0);
	req = dialreq_parse(addr, NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	int accepted_fd = wait_for_accept(loop, listener_fd, TEST_WAIT_SEC);
	int client_fd = result.fd;
	const bool accepted = accepted_fd >= 0;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	T_CHECK(close(listener_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT(has_client_fd);
	T_EXPECT(accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive dialer with req, assert successful CONNECT accepted on final_fd;
 * both produced fds are closed on return. */
T_DECLARE_SUBCASE(
	expect_dial_success, struct ev_loop *restrict loop,
	struct dialreq *restrict req, const struct config *restrict conf,
	struct resolver *restrict resolver, const int final_fd)
{
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, conf, resolver, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	int client_fd = result.fd;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	int accepted_fd = wait_for_accept(loop, final_fd, TEST_WAIT_SEC);
	const bool has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(syserr, 0);
}

T_DECLARE_CASE(direct_connect_domain_resolves_and_succeeds)
{
	struct config conf = test_conf;
	uint_fast16_t final_port;
	int final_fd = make_listener(&final_port);
	struct ev_loop *loop = ev_loop_new(0);
	struct resolver *resolver;
	struct dialreq *req;
	char target_addr[32];

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	req = dialreq_parse(target_addr, NULL);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &conf, resolver, final_fd);
	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

#if WITH_CARES
/*
 * A minimal UDP "DNS server": it echoes the question and appends one A record
 * per address it was given, so a case can dial a name that resolves to more
 * than one address without depending on what this host's /etc/hosts happens to
 * say. Any other query type is answered with no records, which is what an
 * AF_UNSPEC lookup's AAAA half gets. (resolver_test.c drives c-ares through a
 * server of its own: each test binary is self-contained.)
 */
struct fake_dns {
	size_t num_addr;
	struct in_addr addr[2];
};

static void fake_dns_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
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
	/* QTYPE is the field before QCLASS; 1 is A */
	const unsigned qtype =
		((unsigned)buf[q - 4] << 8) | (unsigned)buf[q - 3];
	const size_t num_answer = (qtype == 1) ? dns->num_addr : 0;

	unsigned char resp[600];
	resp[0] = buf[0], resp[1] = buf[1]; /* echo transaction ID */
	resp[2] = 0x81, resp[3] = 0x80; /* QR=1, RD=1, RA=1, RCODE=0 */
	resp[4] = 0x00, resp[5] = 0x01; /* QDCOUNT = 1 */
	resp[6] = 0x00, resp[7] = (unsigned char)num_answer;
	resp[8] = 0x00, resp[9] = 0x00; /* NSCOUNT = 0 */
	resp[10] = 0x00, resp[11] = 0x00; /* ARCOUNT = 0 */
	size_t len = 12;
	memcpy(resp + len, buf + 12, q - 12); /* echo the question */
	len += q - 12;
	for (size_t i = 0; i < num_answer; i++) {
		/* name pointer -> A IN, TTL 0, 4 octets of address */
		static const unsigned char rr[] = {
			0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		};
		(void)memcpy(resp + len, rr, sizeof(rr));
		len += sizeof(rr);
		(void)memcpy(resp + len, &dns->addr[i].s_addr, 4);
		len += 4;
	}

	(void)sendto(
		w->fd, resp, len, 0, (const struct sockaddr *)&from, fromlen);
}

/* Bind the fake nameserver on an ephemeral loopback port, and write the
 * `nameserver' string that points a resolver at it. */
static int make_fake_dns(char *restrict ns, const size_t nslen)
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
	T_CHECK(snprintf(
			ns, nslen, "127.0.0.1:%u",
			(unsigned)ntohs(addr.sin_port)) > 0);
	return fd;
}

/* A TCP socket bound to one named loopback address -- 127.0.0.0/8 is loopback
 * whole, so a case can put one address of a name where it answers and another
 * where it does not. *port selects the port, 0 asking for an ephemeral one and
 * receiving the one bound. A negative backlog leaves the socket unlistened, so
 * connecting to it is refused at once. Returns -1 when the address is already
 * in use. */
static int make_bound_socket(
	const char *restrict ip, uint_fast16_t *restrict port,
	const int backlog)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)*port),
	};
	socklen_t addrlen = sizeof(addr);

	T_CHECK(fd >= 0);
	T_CHECK(inet_pton(AF_INET, ip, &addr.sin_addr) == 1);
	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		T_CHECK(errno == EADDRINUSE);
		T_CHECK(close(fd) == 0);
		return -1;
	}
	if (backlog >= 0) {
		T_CHECK(listen(fd, backlog) == 0);
		T_CHECK(fd_set_nonblock(fd));
	}
	T_CHECK(getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0);
	*port = ntohs(addr.sin_port);
	return fd;
}

/* How many ephemeral ports make_bound_pair() tries before it gives up. */
enum { BOUND_PAIR_ATTEMPTS = 16 };

/* Two TCP sockets bound to one port, fds[0] on ip1 and fds[1] on ip2, for a
 * name that resolves to both addresses and is dialed on that one port. The
 * port is picked ephemeral on ip1, which only makes it free there: anything
 * else on the host may hold it on ip2, so a pair that collides there is
 * dropped for a fresh port. Returns the port. */
static uint_fast16_t make_bound_pair(
	const char *restrict ip1, const int backlog1, const char *restrict ip2,
	const int backlog2, int *restrict fds)
{
	for (int attempt = 1;; attempt++) {
		uint_fast16_t port = 0;
		fds[0] = make_bound_socket(ip1, &port, backlog1);
		T_CHECK(fds[0] >= 0);
		uint_fast16_t port2 = port;
		fds[1] = make_bound_socket(ip2, &port2, backlog2);
		if (fds[1] >= 0) {
			T_CHECK(port2 == port);
			return port;
		}
		T_CHECK(close(fds[0]) == 0);
		T_CHECK(attempt < BOUND_PAIR_ATTEMPTS);
	}
}

/* Occupy a listener's accept queue, so the kernel drops the next SYN rather
 * than refusing it: a connection to that address then neither completes nor
 * fails, which is what an address with no working route looks like. */
static int fill_accept_queue(const char *restrict ip, const uint_fast16_t port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
	};

	T_CHECK(fd >= 0);
	T_CHECK(inet_pton(AF_INET, ip, &addr.sin_addr) == 1);
	T_CHECK(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	return fd;
}

/*
 * Regression: a name commonly resolves to several addresses, and the dialer
 * used to be handed only the first -- so a destination that was reachable
 * failed outright whenever the address the resolver put first was not: the
 * dual-stack name whose IPv6 address has no route, and every multi-record name
 * besides. The nameserver here answers with two addresses; the first is bound
 * but never listens, so it refuses at once, and the listener is on the second.
 * The dial has to reach it.
 */
T_DECLARE_CASE(connect_falls_back_to_the_next_resolved_address)
{
	struct config conf = test_conf;
	struct fake_dns dns = { .num_addr = 2 };
	char nameserver[32];
	const int dns_fd = make_fake_dns(nameserver, sizeof(nameserver));
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &dns.addr[0]) == 1);
	T_CHECK(inet_pton(AF_INET, "127.0.0.2", &dns.addr[1]) == 1);

	/* 127.0.0.2 is the address that answers, on the port the whole name is
	 * dialed on. 127.0.0.1 is the address that refuses: bound, so nothing
	 * else can take the port, and never listening, so the connection to it
	 * is reset at once. It is the one the dial starts on either way -- the
	 * answer's own order puts it first, and so would a resolver sorting by
	 * RFC 6724, 127.0.0.1 being the very address the route to loopback
	 * sources from */
	int fds[2];
	const uint_fast16_t port =
		make_bound_pair("127.0.0.2", 1, "127.0.0.1", -1, fds);
	const int final_fd = fds[0];
	const int dead_fd = fds[1];

	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	w_dns.data = &dns;
	ev_io_start(loop, &w_dns);

	conf.nameserver = nameserver;
	/* the whole answer is carried only for an unpinned query: `-4' / `-6'
	 * still names the one family to resolve in */
	conf.resolve_pf = PF_UNSPEC;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	char target[32];
	T_CHECK(snprintf(
			target, sizeof(target), "test.invalid:%u",
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);

	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &conf, resolver, final_fd);

	dialreq_free(req);
	resolver_free(resolver);
	ev_io_stop(loop, &w_dns);
	ev_loop_destroy(loop);
	T_CHECK(close(dns_fd) == 0);
	T_CHECK(close(dead_fd) == 0);
	T_CHECK(close(final_fd) == 0);
}

/*
 * A blocked address is the egress policy barring that one address, not the
 * destination behind the name: the dial carries on to the next address rather
 * than ending on the blocked one. Of the two addresses answered here one is
 * the loopback the policy is set to block, the other a permitted address whose
 * connection is refused, so a dial that walked both leaves both marks -- the
 * policy's own log line for the blocked address, and the refusal of the
 * permitted one -- while a dial that stopped on the address the resolver put
 * first leaves one of them alone: DIALER_ERR_BLOCKED with nothing refused, or
 * the refusal with nothing blocked.
 *
 * Requiring both marks is what makes the case independent of the answer order,
 * which is not the case's to pick: c-ares hands back the answer sorted per RFC
 * 6724, where a non-routable address is demoted behind a loopback one. The
 * permitted address is TEST-NET-3 (RFC 5737 3), which has a listener nowhere,
 * so the connect() interposer refuses it and the case stays off the network.
 */
T_DECLARE_CASE(connect_advances_past_a_blocked_address)
{
	struct config conf = test_conf;
	struct fake_dns dns = { .num_addr = 2 };
	char nameserver[32];
	const int dns_fd = make_fake_dns(nameserver, sizeof(nameserver));
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &dns.addr[0]) == 1);
	T_CHECK(inet_pton(AF_INET, "203.0.113.1", &dns.addr[1]) == 1);

	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	w_dns.data = &dns;
	ev_io_start(loop, &w_dns);

	conf.nameserver = nameserver;
	conf.resolve_pf = PF_UNSPEC;
	conf.block_loopback = true;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	struct dialreq *const req = dialreq_parse("test.invalid:9", NULL);
	T_CHECK(req != NULL);

	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	g_force_connect_fail = true;
	logcap_start(LOG_LEVEL_DEBUG);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	logcap_stop();
	g_force_connect_fail = false;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	const bool blocked_logged =
		logcap_toplevel_has("blocked loopback address: 127.0.0.1");

	dialreq_free(req);
	resolver_free(resolver);
	ev_io_stop(loop, &w_dns);
	ev_loop_destroy(loop);
	T_CHECK(close(dns_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT_EQ(result.fd, -1);
	/* the policy did bar the loopback address ... */
	if (!blocked_logged) {
		T_FATALF("want the loopback blocked, logged: %s", g_logcap.buf);
	}
	/* ... and the dial did not end there: it got as far as the permitted
	 * address, whose refusal is the error it ends with */
	T_EXPECT_EQ(err, DIALER_ERR_CONNECT);
	T_EXPECT_EQ(syserr, ECONNREFUSED);
}

/*
 * DIALER_ERR_BLOCKED is the verdict on the destination rather than on one
 * address of it, so it is reported only once every address the name resolved
 * to has been blocked -- each of them examined, not just the first. Both
 * addresses here are in the reserved 240.0.0.0/4 (RFC 1112 4), which no
 * configuration permits; the error alone cannot tell the two apart, since a
 * walk ending on the first address reports it just the same, so the policy's
 * own log line for each address is what shows the second was reached. Blocking
 * every address is also what keeps this case independent of the answer order:
 * two addresses of one class rank alike however the resolver sorts them.
 */
T_DECLARE_CASE(connect_reports_blocked_after_every_address_is_blocked)
{
	struct config conf = test_conf;
	struct fake_dns dns = { .num_addr = 2 };
	char nameserver[32];
	const int dns_fd = make_fake_dns(nameserver, sizeof(nameserver));
	T_CHECK(inet_pton(AF_INET, "240.0.0.1", &dns.addr[0]) == 1);
	T_CHECK(inet_pton(AF_INET, "240.0.0.2", &dns.addr[1]) == 1);

	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	w_dns.data = &dns;
	ev_io_start(loop, &w_dns);

	conf.nameserver = nameserver;
	conf.resolve_pf = PF_UNSPEC;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	struct dialreq *const req = dialreq_parse("test.invalid:9", NULL);
	T_CHECK(req != NULL);

	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	logcap_start(LOG_LEVEL_DEBUG);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	logcap_stop();
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	const bool blocked_first =
		logcap_toplevel_has("blocked reserved address: 240.0.0.1");
	const bool blocked_second =
		logcap_toplevel_has("blocked reserved address: 240.0.0.2");

	dialreq_free(req);
	resolver_free(resolver);
	ev_io_stop(loop, &w_dns);
	ev_loop_destroy(loop);
	T_CHECK(close(dns_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(syserr, 0);
	/* the walk did not stop at the first blocked address */
	if (!blocked_first || !blocked_second) {
		T_FATALF(
			"want both addresses blocked, logged: %s",
			g_logcap.buf);
	}
}

/*
 * An address that neither connects nor fails -- its SYN silently dropped, the
 * everyday shape of a destination with no working route -- must not hold the
 * dial until its owner's timeout expires. The attempts are staggered instead
 * (RFC 8305 5): the next address is tried while the first is still in the
 * handshake, and the one that answers wins. The first address here is a
 * listener whose accept queue is already full, which is what makes the kernel
 * drop the dialer's SYN.
 */
T_DECLARE_CASE(connect_advances_past_an_address_that_stalls)
{
	struct config conf = test_conf;
	struct fake_dns dns = { .num_addr = 2 };
	char nameserver[32];
	const int dns_fd = make_fake_dns(nameserver, sizeof(nameserver));
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &dns.addr[0]) == 1);
	T_CHECK(inet_pton(AF_INET, "127.0.0.2", &dns.addr[1]) == 1);

	/* 127.0.0.1 is the address that stalls: a listener with no room to
	 * accept. 127.0.0.2 is the address that answers */
	int fds[2];
	const uint_fast16_t port =
		make_bound_pair("127.0.0.1", 0, "127.0.0.2", 1, fds);
	const int stalled_fd = fds[0];
	const int final_fd = fds[1];
	const int filler_fd = fill_accept_queue("127.0.0.1", port);

	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	w_dns.data = &dns;
	ev_io_start(loop, &w_dns);

	conf.nameserver = nameserver;
	conf.resolve_pf = PF_UNSPEC;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	char target[32];
	T_CHECK(snprintf(
			target, sizeof(target), "test.invalid:%u",
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);

	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &conf, resolver, final_fd);

	dialreq_free(req);
	resolver_free(resolver);
	ev_io_stop(loop, &w_dns);
	ev_loop_destroy(loop);
	T_CHECK(close(dns_fd) == 0);
	T_CHECK(close(filler_fd) == 0);
	T_CHECK(close(stalled_fd) == 0);
	T_CHECK(close(final_fd) == 0);
}

static bool dialer_connecting_predicate(void *data)
{
	const struct dialer *const d = data;
	return d->state == DIALER_STATE_CONNECT;
}

/* Collect the sockets of the connection attempts in flight into @p fds. */
static size_t attempt_fds(const struct dialer *restrict d, int *restrict fds)
{
	size_t n = 0;
	for (size_t i = 0; i < ARRAY_SIZE(d->w_attempt); i++) {
		if (d->w_attempt[i].fd >= 0) {
			fds[n++] = d->w_attempt[i].fd;
		}
	}
	return n;
}

/* Whether nothing of the connect phase is left running: every attempt socket
 * in @p fds closed (not leaked), every attempt watcher stopped and cleared, and
 * the stagger timer stopped, so no further address can be tried. */
static bool attempts_torn_down(
	const struct dialer *restrict d, const int *restrict fds,
	const size_t num_fds)
{
	for (size_t i = 0; i < num_fds; i++) {
		if (fcntl(fds[i], F_GETFD) >= 0 || errno != EBADF) {
			return false;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(d->w_attempt); i++) {
		if (d->w_attempt[i].fd != -1 ||
		    ev_is_active(&d->w_attempt[i])) {
			return false;
		}
	}
	return d->num_inflight == 0 && !ev_is_active(&d->w_delay);
}

/*
 * dialer_cancel() while connecting must tear down every attempt in flight and
 * stop the stagger timer, so that no further address is tried after the
 * cancel. Both addresses the name resolves to stall -- listeners whose accept
 * queues are already full -- so the first attempt is still in flight when the
 * dial is observed in DIALER_STATE_CONNECT, with the delay armed that would
 * start the second.
 */
T_DECLARE_CASE(dialer_cancel_during_connect_stops_every_attempt)
{
	struct config conf = test_conf;
	struct fake_dns dns = { .num_addr = 2 };
	char nameserver[32];
	const int dns_fd = make_fake_dns(nameserver, sizeof(nameserver));
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &dns.addr[0]) == 1);
	T_CHECK(inet_pton(AF_INET, "127.0.0.2", &dns.addr[1]) == 1);

	int fds[2];
	const uint_fast16_t port =
		make_bound_pair("127.0.0.1", 0, "127.0.0.2", 0, fds);
	const int stalled1_fd = fds[0];
	const int stalled2_fd = fds[1];
	const int filler1_fd = fill_accept_queue("127.0.0.1", port);
	const int filler2_fd = fill_accept_queue("127.0.0.2", port);

	struct ev_loop *const loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	ev_io w_dns;
	ev_io_init(&w_dns, fake_dns_cb, dns_fd, EV_READ);
	w_dns.data = &dns;
	ev_io_start(loop, &w_dns);

	conf.nameserver = nameserver;
	conf.resolve_pf = PF_UNSPEC;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);

	char target[32];
	T_CHECK(snprintf(
			target, sizeof(target), "test.invalid:%u",
			(unsigned)port) > 0);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);

	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool connecting = test_wait_until(
		loop, dialer_connecting_predicate, &d, TEST_WAIT_SEC, NULL,
		NULL);
	const size_t inflight = d.num_inflight;
	const bool delay_armed = ev_is_active(&d.w_delay);
	int attempt_fd[ARRAY_SIZE(d.w_attempt)];
	const size_t num_attempt_fd = attempt_fds(&d, attempt_fd);

	dialer_cancel(&d, loop);
	const enum dialer_error err = d.err;
	const enum dialer_state state = d.state;
	const bool torn_down =
		attempts_torn_down(&d, attempt_fd, num_attempt_fd);
	(void)ev_run(loop, EVRUN_NOWAIT);

	dialreq_free(req);
	resolver_free(resolver);
	ev_io_stop(loop, &w_dns);
	ev_loop_destroy(loop);
	T_CHECK(close(dns_fd) == 0);
	T_CHECK(close(filler1_fd) == 0);
	T_CHECK(close(stalled1_fd) == 0);
	T_CHECK(close(filler2_fd) == 0);
	T_CHECK(close(stalled2_fd) == 0);

	T_EXPECT(connecting);
	T_EXPECT_EQ(inflight, 1);
	T_EXPECT_EQ(num_attempt_fd, 1);
	T_EXPECT(delay_armed);
	T_EXPECT(torn_down);
	T_EXPECT_EQ(err, DIALER_CANCELLED);
	T_EXPECT_EQ(state, DIALER_STATE_DONE);
	T_EXPECT(!result.called);
	T_EXPECT_EQ(result.fd, -1);
}
#endif /* WITH_CARES */

/*
 * resolve_cb() is handed a NULL address whenever a name cannot be resolved, and
 * the dial has to end as DIALER_ERR_RESOLVE with no fd. The name below is
 * refused for its shape -- RFC 1035 2.3.1 caps a label at 63 octets -- so both
 * the c-ares and the getaddrinfo() back end answer out of the query encoder,
 * without a packet on the wire or a wait on a nameserver.
 */
T_DECLARE_CASE(resolve_failure_reports_resolve_error)
{
	struct config conf = test_conf;
	char target[256];
	memset(target, 'a', 200);
	T_CHECK(snprintf(target + 200, sizeof(target) - 200, ":80") > 0);

	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);
	T_CHECK(req->addr.type == ATYP_DOMAIN);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_RESOLVE);
	T_EXPECT_EQ(syserr, 0);
}

/*
 * resolve_do() fails only on out-of-memory, and dialer_start() has to turn that
 * into a failed dial: left as DIALER_OK the finished dial would report success
 * and the caller relay fd -1 as an established connection. The interposer fails
 * exactly the query allocation -- the first malloc() after dialer_do() -- so
 * nothing else in the path is disturbed.
 */
T_DECLARE_CASE(resolve_alloc_failure_reports_system_error)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	struct dialreq *const req = dialreq_parse("localhost:80", NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	g_malloc_fail_once = true;
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool failed_alloc = !g_malloc_fail_once;
	g_malloc_fail_once = false;
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);

	/* the armed failure was consumed by the query allocation */
	T_EXPECT(failed_alloc);
	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_SYSTEM);
	T_EXPECT_EQ(syserr, ENOMEM);
}

/* The shared verdict of the cases below. */
T_DECLARE_SUBCASE(logcap_expect_no_forged_line, const char *restrict marker)
{
	/* something was logged about the rejection ... */
	T_EXPECT(g_logcap.len > 0);
	/* ... the capture holds the whole run, so an absence means something
	 * (io_memwriter drops silently what does not fit) ... */
	T_EXPECT(g_logcap.len < sizeof(g_logcap.buf) - 1);
	/* ... and no line began with the peer's bytes */
	T_EXPECT(!logcap_toplevel_has(marker));
	/* nor did a byte that drives a terminal or a log parser survive */
	T_EXPECT(memchr(g_logcap.buf, '\r', g_logcap.len) == NULL);
	T_EXPECT(memchr(g_logcap.buf, '\x01', g_logcap.len) == NULL);
}

T_DECLARE_SUBCASE(
	expect_bad_address_logs_no_forged_line, const char *restrict s,
	const size_t len, const char *restrict want)
{
	struct dialaddr addr = { 0 };

	logcap_start(LOG_LEVEL_DEBUG);
	const bool ok = dialaddr_parse(&addr, s, len);
	logcap_stop();

	T_EXPECT(!ok);
	/* the branch under test, not another one that also refuses the input */
	if (strstr(g_logcap.buf, want) == NULL) {
		T_FATALF("want `%s', logged: %s", want, g_logcap.buf);
	}
	T_CALL_SUBCASE(logcap_expect_no_forged_line, "forged");
}

/*
 * A SOCKS5 DOMAINNAME is a length-prefixed byte string with no character set
 * of its own (RFC 1928, 5), so the address the dialer parses is whatever the
 * peer wrote. Rendering it with %s let a newline in it end the log line,
 * leaving everything after it a line the peer composed -- at error level,
 * which prints at the default log level (CWE-117).
 */
T_DECLARE_CASE(dialaddr_parse_log_keeps_client_bytes_off_the_line)
{
	static const struct {
		const char *s;
		const char *want;
	} bad[] = {
		/* an unbracketed second colon */
		{ "a:b\nE forged\r\x01:80", "invalid address:" },
		/* brackets around something that is not an IPv6 literal */
		{ "[foo\nE forged\r\x01]:80", "not an IPv6 literal:" },
		/* trailing garbage in the port number */
		{ "[::1]:9\nE forged\r\x01", "unable to parse port number:" },
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		T_CALL_SUBCASE(
			expect_bad_address_logs_no_forged_line, bad[i].s,
			strlen(bad[i].s), bad[i].want);
	}

	/* a null byte: it ends every %s short of the length dialaddr_parse()
	 * was handed, so only that length carries the rest of the address */
	static const char withnul[] = "a\0b\nE forged\r\x01:80";
	T_CALL_SUBCASE(
		expect_bad_address_logs_no_forged_line, withnul,
		sizeof(withnul) - 1, "invalid address:");

	/* a host past FQDN_MAX_LENGTH that still forms an authority, so the
	 * "hostname too long" branch is reached rather than the length check
	 * dialaddr_parse() makes first */
	char toolong[DIALADDR_STRLEN + 1];
	const size_t fill = FQDN_MAX_LENGTH - CONSTSTRLEN("\nE forged") + 1;
	memset(toolong, 'a', fill);
	memcpy(toolong + fill, "\nE forged:80", CONSTSTRLEN("\nE forged:80"));
	T_CALL_SUBCASE(
		expect_bad_address_logs_no_forged_line, toolong,
		fill + CONSTSTRLEN("\nE forged:80"), "hostname too long:");
}

T_DECLARE_SUBCASE(
	expect_bad_proxy_uri_logs_no_forged_line, const char *restrict csv,
	const char *restrict want)
{
	logcap_start(LOG_LEVEL_DEBUG);
	struct dialreq *const req = dialreq_parse("203.0.113.1:80", csv);
	logcap_stop();

	if (req != NULL) {
		dialreq_free(req);
		T_FATALF("accepted an invalid proxy uri: `%s'", csv);
	}
	/* the branch under test, not another one that also refuses the uri */
	if (strstr(g_logcap.buf, want) == NULL) {
		T_FATALF("want `%s', logged: %s", want, g_logcap.buf);
	}
	T_CALL_SUBCASE(logcap_expect_no_forged_line, "forged");
}

/* The proxy chain is a ruleset result, so it too can carry bytes the peer
 * chose. Its rejection lines rendered the uri with %s against a pointer that
 * is not null-terminated at urilen, so they printed past the element as well
 * as splicing its bytes into the line. url_parse() refuses a raw control byte
 * anywhere in a uri, so the two lines a hostile uri can reach are the parse
 * failure itself and the userinfo one, whose bytes arrive percent-encoded and
 * are decoded in place before it logs them. */
T_DECLARE_CASE(dialreq_parse_log_keeps_proxy_uri_bytes_off_the_line)
{
	T_CALL_SUBCASE(
		expect_bad_proxy_uri_logs_no_forged_line,
		"E forged\r\x01 not a uri", "unable to parse uri:");

	/* a decoded credential too long for struct proxyreq's storage: the
	 * branch that logs the userinfo, by then holding the decoded bytes */
	char pad[600];
	memset(pad, 'a', sizeof(pad) - 1);
	pad[sizeof(pad) - 1] = '\0';
	char uri[1024];
	T_CHECK(snprintf(
			uri, sizeof(uri),
			"socks5://%%0AE%%20forged%%0D%%01%s@host:1080",
			pad) > 0);
	T_CALL_SUBCASE(
		expect_bad_proxy_uri_logs_no_forged_line, uri,
		"invalid proxy userinfo:");
}

/*
 * The name the dialer starts a request on and reports a failed resolution for
 * is the peer's own. A control byte no longer reaches here -- such a name is
 * not a host name and fails the dial before it starts -- so the bytes below are
 * the printable ones a peer may still pick: the quote that closes a quoted
 * value and the backslash that introduces an escape. The label is far past RFC
 * 1035 2.3.1's 63 octets, so both the c-ares and the getaddrinfo() back end
 * refuse it out of the query encoder -- no packet on the wire, no wait on a
 * nameserver.
 */
T_DECLARE_CASE(dial_log_keeps_client_name_off_the_line)
{
	struct config conf = test_conf;
	char target[DIALADDR_STRLEN + 1];
	const size_t fill = 200;
	memset(target, 'a', fill);
	memcpy(target + fill, "'E\\forged:80", CONSTSTRLEN("'E\\forged:80"));
	const size_t targetlen = fill + CONSTSTRLEN("'E\\forged:80");
	target[targetlen] = '\0';

	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	struct resolver *const resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	struct dialreq *const req = dialreq_parse(target, NULL);
	T_CHECK(req != NULL);
	T_CHECK(req->addr.type == ATYP_DOMAIN);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);

	logcap_start(LOG_LEVEL_VERBOSE);
	dialer_do(&d, loop, req, &conf, resolver, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	logcap_stop();

	const enum dialer_error err = d.err;
	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(err, DIALER_ERR_RESOLVE);
	T_CALL_SUBCASE(logcap_expect_no_forged_line, "forged");
	/* the name is still logged, just never as part of a line */
	T_EXPECT(strstr(g_logcap.buf, "aaaaaaaa") != NULL);
}

/* The shared verdict of the prefix cases below. */
T_DECLARE_SUBCASE(logcap_expect_one_line_per_entry, const char *restrict want)
{
	/* something was logged ... */
	T_EXPECT(g_logcap.len > 0);
	/* ... the capture holds the whole run, so an absence means something
	 * (io_memwriter drops silently what does not fit) ... */
	T_EXPECT(g_logcap.len < sizeof(g_logcap.buf) - 1);
	/* ... the line under test is there, escaped as expected ... */
	if (strstr(g_logcap.buf, want) == NULL) {
		T_FATALF("want `%s', logged: %s", want, g_logcap.buf);
	}
	/* ... every line is one slog began, so nothing the peer wrote started
	 * one ... */
	T_EXPECT(logcap_lines_wellformed());
	/* ... nor did a byte that drives a terminal or a log parser survive */
	T_EXPECT(memchr(g_logcap.buf, '\r', g_logcap.len) == NULL);
	T_EXPECT(memchr(g_logcap.buf, '\x01', g_logcap.len) == NULL);
}

/*
 * The per-request prefix every DIALER_LOG_F line carries renders the
 * destination, which for a proxied dial is the name the peer wrote. Spliced in
 * verbatim, a newline in it ended the line there and left the rest an entry the
 * peer composed. LOG_TXT_F() does not fit a context prefix -- the writer sink
 * below, which the syslog sink matches, renders no struct slog_extra, so every
 * line in the module would lose its request context there -- so the prefix is
 * escaped inline and asserted through both sinks. A name reaching the prefix is
 * printable ASCII by now, which leaves the quote that would close the value and
 * the backslash that introduces an escape.
 */
T_DECLARE_SUBCASE(expect_dial_status_log_escaped, const enum logcap_sink sink)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_NOALLOWED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	struct dialreq *const req =
		dialreq_parse("a'E\\forged.example:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);

	logcap_start_sink(LOG_LEVEL_DEBUG, sink);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC,
		socks5_raw_pump, &server);
	logcap_stop();

	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
	T_CALL_SUBCASE(
		logcap_expect_one_line_per_entry,
		"connect `a\\'E\\\\forged.example:443' over [0] "
		"`socks5://127.0.0.1:");
}

T_DECLARE_CASE(dial_status_log_keeps_client_name_on_one_line)
{
	T_CALL_SUBCASE(expect_dial_status_log_escaped, LOGCAP_STREAM);
	T_CALL_SUBCASE(expect_dial_status_log_escaped, LOGCAP_WRITER);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(dialaddr_parse_and_format_variants),
	T_CASE(dialaddr_parse_rejects_embedded_nul),
	T_CASE(dialreq_addproxy_rejects_embedded_nul),
	T_CASE(dialaddr_parse_rejects_invalid_authority),
	T_CASE(dialaddr_parse_rejects_a_name_no_request_can_carry),
	T_CASE(dialaddr_parse_rejects_an_empty_name),
	T_CASE(dialaddr_parse_requires_a_port_a_connection_reaches),
	T_CASE(format_max_length_domain_fits_buffers),
	T_CASE(dialaddr_set_and_copy),
	T_CASE(dialreq_parse_and_format_proxy_chain),
	T_CASE(dialreq_parse_accepts_the_forward_placeholder),
	T_CASE(dialreq_parse_scheme_default_ports),
	T_CASE(dialreq_parse_empty_proxy_port_is_the_scheme_default),
	T_CASE(dialreq_parse_bracketed_ipv6_proxy_authority),
	T_CASE(dialreq_parse_rejects_ambiguous_proxy_authority),
	T_CASE(dialreq_parse_rejects_bracketed_non_ipv6_proxy_authority),
	T_CASE(dialreq_parse_rejects_bad_proxy_uris),
	T_CASE(dialreq_parse_rejects_overlong_proxy_uri),
	T_CASE(dialreq_parse_bounds_chain_before_allocating),
	T_CASE(dialreq_addproxy_rejects_a_full_chain),
	T_CASE(dialreq_new_rejects_an_oversized_credential),
	T_CASE(dialreq_copies_a_max_length_credential),
	T_CASE(dialreq_replace_swaps_on_success),
	T_CASE(dialreq_replace_keeps_old_on_failure),
	T_CASE(dialreq_new_copies_base_request),
	T_CASE(dialer_strerror_known_and_unknown),
	T_CASE(direct_connect_reports_success),
	T_CASE(direct_connect_ipv6_reports_success),
	T_CASE(local_address_blocked_by_egress_policy),
	T_CASE(v4_mapped_local_address_blocked_by_egress_policy),
	T_CASE(v4_mapped_loopback_address_blocked_by_egress_policy),
	T_CASE(shared_cgnat_address_is_dialable_by_default),
	T_CASE(connect_failure_reports_errno),
	T_CASE(socket_setup_failure_reports_setter_errno),
	T_CASE(reserved_address_blocked_by_egress_policy),
	T_CASE(http_connect_success_sends_expected_request),
	T_CASE(dial_refuses_a_name_no_request_can_carry),
	T_CASE(dial_refuses_an_empty_name),
	T_CASE(dial_refuses_a_port_no_connection_reaches),
	T_CASE(dial_over_an_empty_proxy_port_uses_the_scheme_default),
	T_CASE(sync_connect_success_into_http_handshake),
	T_CASE(http_connect_success_with_byte_at_a_time_response),
	T_CASE(http_connect_split_response_reports_success),
	T_CASE(http_connect_success_with_large_response_headers),
	T_CASE(http_connect_success_with_fragmented_large_header_line),
	T_CASE(http_connect_407_maps_to_proxy_auth),
	T_CASE(http_connect_403_maps_to_proxy_reject),
	T_CASE(http_connect_502_maps_to_proxy_refused),
	T_CASE(http_connect_non_200_maps_to_proxy_proto),
	T_CASE(http_connect_malformed_header_maps_to_proxy_proto),
	T_CASE(http_connect_unsupported_version_maps_to_proxy_proto),
	T_CASE(http_connect_malformed_version_maps_to_proxy_proto),
	T_CASE(http_connect_2xx_reports_success),
	T_CASE(http_connect_interim_1xx_reports_success),
	T_CASE(http_connect_large_interim_responses_reclaim_buffer),
	T_CASE(http_connect_many_interim_responses_reclaim_buffer),
	T_CASE(http_connect_invalid_status_code_maps_to_proxy_proto),
	T_CASE(http_connect_oversized_response_maps_to_proxy_proto),
	T_CASE(http_connect_leaves_tunnel_bytes_on_the_socket),
	T_CASE(http_connect_header_block_at_the_buffer_limit),
	T_CASE(socks4a_rejected_maps_to_proxy_refused),
	T_CASE(socks4a_identd_failures_map_to_reject_and_auth),
	T_CASE(socks4a_granted_reports_success),
	T_CASE(socks4a_granted_leaves_tunnel_bytes_on_the_socket),
	T_CASE(socks4a_sends_userid),
	T_CASE(socks4a_ipv6_target_encodes_hostname),
	T_CASE(socks5_noallowed_maps_to_proxy_reject),
	T_CASE(socks5_connect_success),
	T_CASE(socks5_connect_ipv4_target_encoding),
	T_CASE(socks5_connect_ipv6_target_encoding),
	T_CASE(socks5_connect_success_domain_bnd_addr),
	T_CASE(socks5_connect_leaves_tunnel_bytes_on_the_socket),
	T_CASE(socks5_oversized_username_fails),
	T_CASE(socks5_userpass_auth_success),
	T_CASE(socks5_unoffered_userpass_maps_to_proxy_proto),
	T_CASE(socks5_no_acceptable_method_maps_to_proxy_auth),
	T_CASE(socks5_userpass_request_encodes_the_credential),
	T_CASE(socks5_userpass_failure_maps_to_proxy_auth),
	T_CASE(socks5_reply_failures_map_to_dialer_errors),
	T_CASE(socks5_method_selection_errors_map_to_proxy_proto),
	T_CASE(socks4a_reply_version_maps_to_proxy_proto),
	T_CASE(socks5_redial_after_success_resets_state),
	T_CASE(socks5_chain_two_hops_success),
	T_CASE(proxy_eof_mid_handshake_maps_to_eof),
	T_CASE(dialer_cancel_stops_in_flight_dial),
	T_CASE(dialer_cancel_during_resolve_drops_the_query),
	T_CASE(dialer_cancel_withdraws_a_fed_finish),
	T_CASE(direct_connect_domain_resolves_and_succeeds),
#if WITH_CARES
	T_CASE(connect_falls_back_to_the_next_resolved_address),
	T_CASE(connect_advances_past_a_blocked_address),
	T_CASE(connect_reports_blocked_after_every_address_is_blocked),
	T_CASE(connect_advances_past_an_address_that_stalls),
	T_CASE(dialer_cancel_during_connect_stops_every_attempt),
#endif
	T_CASE(resolve_failure_reports_resolve_error),
	T_CASE(resolve_alloc_failure_reports_system_error),
	T_CASE(dialaddr_parse_log_keeps_client_bytes_off_the_line),
	T_CASE(dialreq_parse_log_keeps_proxy_uri_bytes_off_the_line),
	T_CASE(dial_log_keeps_client_name_off_the_line),
	T_CASE(dial_status_log_keeps_client_name_on_one_line),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	resolver_init();
	const int ret = testing_main(argc, argv, suite);
	resolver_cleanup();
	return ret;
}
