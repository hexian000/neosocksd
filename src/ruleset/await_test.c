/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * await_test - white-box unit tests for ruleset/await.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/await.c  module under test
 *   ruleset/base.c   ruleset Lua substrate
 *   proto/codec.c    leaf
 * The dialer/resolver/api_client/server symbols bound by await.c are replaced
 * by the mocks in the mock section below.
 */

#include "await.h"

#include "api_client.h"
#include "base.h"
#include "cfunc.h"
#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "server.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * virtual clock - fire await.sleep(delay)'s Lua-owned ev_timer deterministically
 * with no wall-clock wait. The strong-symbol interposers return a test-advanced
 * virtual time while enabled and pass through to the real clock otherwise, so
 * every other case is unaffected.
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
 * has a consistent virtual deadline the test crosses by advancing. */
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
 * kill trace - record what await.execute's close handler signals, so a pass
 * that must signal nothing is distinguishable from one that signals a pid this
 * process no longer owns. Delivery is reimplemented over sigqueue(), which
 * needs no libc-internal symbol; it addresses a single process, so the
 * process-group form (-pid) is delivered to the group leader. Every child these
 * cases spawn is a single-process session, so the leader is the whole group.
 * Delivery is switched off where the recorded pid is already reaped, so an
 * unfixed handler cannot signal whatever recycled that pid.
 * ---------------------------------------------------------------------- */

static bool g_fork_fail;
static size_t g_fork_calls;

pid_t test_await_fork(void);

pid_t test_await_fork(void)
{
	g_fork_calls++;
	if (g_fork_fail) {
		errno = EAGAIN;
		return -1;
	}
	return fork();
}

struct kill_call {
	pid_t pid;
	int sig;
};

static struct kill_call g_kill_calls[4];
static size_t g_kill_count = 0;
static bool g_kill_deliver = true;

int kill(pid_t pid, int sig)
{
	if (g_kill_count < ARRAY_SIZE(g_kill_calls)) {
		g_kill_calls[g_kill_count] = (struct kill_call){
			.pid = pid,
			.sig = sig,
		};
	}
	g_kill_count++;
	if (!g_kill_deliver) {
		return 0;
	}
	const union sigval value = { .sival_int = 0 };
	return sigqueue(pid < 0 ? -pid : pid, sig, value);
}

static void kill_trace_reset(void)
{
	g_kill_count = 0;
	g_kill_deliver = true;
}

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (dialer, resolver, api_client, server) and
 * shared fixtures.
 * ---------------------------------------------------------------------- */

static const ev_tstamp TEST_WAIT_SEC = 0.128;

struct test_watchdog {
	bool fired;
};

struct string_stream {
	struct io_stream stream;
	const char *text;
	size_t len;
	bool consumed;
};

struct lua_global_pred {
	lua_State *L;
	const char *name;
};

static struct {
	struct ev_loop *loop;
	bool resolve_start_ok;
	struct resolve_query *resolve_query;
	struct resolve_cb resolve_cb;
	bool api_start_ok;
	struct api_client_ctx *api_ctx;
	struct api_client_cb api_cb;
	struct dialreq *req;
	char payload[256];
	size_t payload_len;
	bool api_cancelled;
	bool resolve_cancelled;
	/* await.forward dialer stub state */
	struct dialer *dial_d;
	bool dial_pending;
	bool dial_cancelled;
} STUB = {
	.loop = NULL,
	.resolve_start_ok = true,
	.resolve_query = NULL,
	.resolve_cb = { 0 },
	.api_start_ok = true,
	.api_ctx = NULL,
	.api_cb = { 0 },
	.req = NULL,
	.payload = { 0 },
	.payload_len = 0,
	.api_cancelled = false,
	.resolve_cancelled = false,
	.dial_d = NULL,
	.dial_pending = false,
	.dial_cancelled = false,
};

static void reset_stub_state(void)
{
	/* clear a virtual clock a prior timeout case may have left enabled on a
	 * T_EXPECT failure path, and likewise a suppressed signal delivery */
	vclock_stop();
	kill_trace_reset();
	if (STUB.resolve_query != NULL) {
		free(STUB.resolve_query);
		STUB.resolve_query = NULL;
	}
	if (STUB.api_ctx != NULL) {
		free(STUB.api_ctx);
		STUB.api_ctx = NULL;
	}
	if (STUB.req != NULL) {
		dialreq_free(STUB.req);
		STUB.req = NULL;
	}
	STUB.resolve_start_ok = true;
	STUB.resolve_cb = (struct resolve_cb){ 0 };
	STUB.api_start_ok = true;
	STUB.api_cb = (struct api_client_cb){ 0 };
	STUB.payload[0] = '\0';
	STUB.payload_len = 0;
	STUB.api_cancelled = false;
	STUB.resolve_cancelled = false;
	STUB.dial_d = NULL;
	STUB.dial_pending = false;
	STUB.dial_cancelled = false;
}

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		if (predicate(data)) {
			ev_timer_stop(loop, &w_timeout);
			return true;
		}
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static bool global_is_non_nil(void *data)
{
	const struct lua_global_pred *const pred = data;
	const int tp = lua_getglobal(pred->L, pred->name);

	lua_pop(pred->L, 1);
	return tp != LUA_TNIL;
}

static int string_stream_direct_read(void *data, const void **buf, size_t *len)
{
	struct string_stream *const s = data;

	if (s->consumed) {
		*buf = NULL;
		*len = 0;
		return 0;
	}
	s->consumed = true;
	*buf = s->text;
	*len = s->len;
	return 0;
}

static const struct io_stream_vftable string_stream_vftable = {
	.direct_read = string_stream_direct_read,
};

static struct io_stream *
string_stream_open(struct string_stream *restrict s, const char *restrict text)
{
	*s = (struct string_stream){
		.stream = {
			.vftable = &string_stream_vftable,
			.data = s,
		},
		.text = text,
		.len = strlen(text),
		.consumed = false,
	};
	return &s->stream;
}

static bool parse_hostport(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	char buf[256];
	char *host = buf;
	char *port = NULL;

	if (len >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, s, len);
	buf[len] = '\0';
	if (buf[0] == '[') {
		char *end = strchr(buf, ']');
		if (end == NULL || end[1] != ':') {
			return false;
		}
		*end = '\0';
		host = buf + 1;
		port = end + 2;
	} else {
		port = strrchr(buf, ':');
		if (port == NULL) {
			return false;
		}
		*port++ = '\0';
	}
	addr->port = (uint_least16_t)strtoul(port, NULL, 10);
	if (inet_pton(AF_INET, host, &addr->in) == 1) {
		addr->type = ATYP_INET;
		return true;
	}
	if (inet_pton(AF_INET6, host, &addr->in6) == 1) {
		addr->type = ATYP_INET6;
		return true;
	}
	addr->type = ATYP_DOMAIN;
	addr->domain.len = (uint_least8_t)strlen(host);
	memcpy(addr->domain.name, host, addr->domain.len);
	return true;
}

/*
 * await.c and base.c are included as sources.  The stubs below satisfy
 * their external symbol dependencies while allowing the coroutine-based
 * happy paths to be driven deterministically from the tests.
 */

/* ---- dialer stubs (required by base.c's aux_todialreq) ---- */

const char *const proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

/* issue #19 regression: count live dialreqs and inject a one-shot Lua
 * allocation failure right after aux_todialreq builds one, to prove req is
 * never leaked when a fallible Lua op raises before ownership transfer. */
static int g_dialreq_live = 0;
static bool g_oom_arm_on_dialreq =
	false; /* next dialreq_new arms the failure */
static int g_oom_fail_count = 0; /* fail this many upcoming Lua allocations */

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	const size_t base_num_proxy = (base != NULL) ? base->num_proxy : 0;
	struct dialreq *const req =
		calloc(1, sizeof(*req) + (base_num_proxy + num_proxy) *
						 sizeof(req->proxy[0]));

	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = base_num_proxy;
	if (base != NULL) {
		req->addr = base->addr;
		memcpy(req->proxy, base->proxy,
		       base_num_proxy * sizeof(req->proxy[0]));
	}
	g_dialreq_live++;
	if (g_oom_arm_on_dialreq) {
		/* req is now built but not yet owned: fail the next Lua allocation
		 * (twice, to defeat Lua's emergency-GC-and-retry) */
		g_oom_arm_on_dialreq = false;
		g_oom_fail_count = 2;
	}
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	char buf[256];
	char *scheme;
	char *hostport;
	struct proxyreq *proxy;

	if (req == NULL || urilen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, proxy_uri, urilen);
	buf[urilen] = '\0';
	scheme = buf;
	hostport = strstr(buf, "://");
	if (hostport == NULL) {
		return false;
	}
	*hostport = '\0';
	hostport += 3;
	proxy = &req->proxy[req->num_proxy++];
	if (strcmp(scheme, "http") == 0) {
		proxy->proto = PROTO_HTTP;
	} else if (strcmp(scheme, "socks4a") == 0) {
		proxy->proto = PROTO_SOCKS4A;
	} else if (strcmp(scheme, "socks5") == 0) {
		proxy->proto = PROTO_SOCKS5;
	} else {
		return false;
	}
	return parse_hostport(&proxy->addr, hostport, strlen(hostport));
}

void dialreq_free(struct dialreq *req)
{
	if (req != NULL) {
		g_dialreq_live--;
	}
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	return parse_hostport(addr, s, len);
}

/* ---- dialer stubs (required by await.c's await_forward) ---- */

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *const byt_sent, uint_least64_t *const byt_recv)
{
	(void)byt_sent;
	(void)byt_recv;
	d->finish_cb = *callback;
	d->dialed_fd = -1;
	d->err = DIALER_OK;
	d->syserr = 0;
}

void dialer_do(
	struct dialer *restrict d, struct ev_loop *loop,
	const struct dialreq *restrict req, const struct config *restrict conf,
	struct resolver *restrict resolver, struct server *restrict server)
{
	(void)conf;
	(void)resolver;
	(void)server;
	STUB.loop = loop;
	STUB.dial_d = d;
	STUB.dial_pending = true;
	d->req = req;
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	(void)loop;
	STUB.dial_cancelled = true;
	if (STUB.dial_d == d) {
		STUB.dial_pending = false;
		STUB.dial_d = NULL;
	}
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub dialer error";
}

/* ---- resolver stubs (required by await.c's await_resolve) ---- */

struct resolve_query *resolve_do(
	struct resolver *restrict r, const struct resolve_cb cb,
	const char *restrict name, const char *restrict service,
	const int family)
{
	(void)r;
	(void)name;
	(void)service;
	(void)family;
	if (!STUB.resolve_start_ok) {
		return NULL;
	}
	STUB.resolve_query = malloc(1);
	if (STUB.resolve_query == NULL) {
		return NULL;
	}
	STUB.resolve_cb = cb;
	return STUB.resolve_query;
}

void resolve_cancel(struct resolve_query *q)
{
	STUB.resolve_cancelled = true;
	free(q);
	if (STUB.resolve_query == q) {
		STUB.resolve_query = NULL;
	}
}

/* ---- api_client stubs (required by await.c's await_invoke) ---- */

bool api_client_rpcall(
	struct ev_loop *restrict loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const void *restrict payload, size_t len,
	const struct api_client_cb *restrict cb,
	const struct api_client_opts *restrict opts)
{
	(void)opts;
	/* mirror api_client_do: req ownership transfers here and it is freed
	 * on every failure path */
	if (!STUB.api_start_ok) {
		dialreq_free(req);
		return false;
	}
	STUB.loop = loop;
	STUB.api_ctx = malloc(1);
	if (STUB.api_ctx == NULL) {
		dialreq_free(req);
		return false;
	}
	*pctx = STUB.api_ctx;
	STUB.api_cb = *cb;
	STUB.req = req;
	STUB.payload_len =
		len < sizeof(STUB.payload) - 1 ? len : sizeof(STUB.payload) - 1;
	memcpy(STUB.payload, payload, STUB.payload_len);
	STUB.payload[STUB.payload_len] = '\0';
	return true;
}

void api_client_cancel(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx)
{
	(void)loop;
	STUB.api_cancelled = true;
	free(ctx);
	if (STUB.api_ctx == ctx) {
		STUB.api_ctx = NULL;
	}
}

/* ---- Lua helpers ---- */

/* A realloc-based lua_Alloc that fails its next non-free allocation once when
 * g_oom_armed is set (issue #19 regression). The caller must preserve the
 * allocator ud as the ruleset pointer so aux_getruleset keeps working. */
static void *
test_failing_alloc(void *ud, void *ptr, const size_t osize, const size_t nsize)
{
	(void)ud;
	(void)osize;
	if (nsize == 0) {
		free(ptr);
		return NULL;
	}
	if (g_oom_fail_count > 0) {
		g_oom_fail_count--;
		return NULL;
	}
	return realloc(ptr, nsize);
}

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_await(L);
	lua_setglobal(L, "await");
	return L;
}

static lua_State *new_ruleset_lua(
	struct ruleset *restrict r, struct config *restrict conf,
	struct ev_loop *loop)
{
	lua_State *restrict L = luaL_newstate();
	lua_Alloc alloc;

	T_CHECK(L != NULL);
	alloc = lua_getallocf(L, NULL);
	lua_setallocf(L, alloc, r);
	luaL_openlibs(L);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	aux_newweaktable(L, "k");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
	r->loop = loop;
	r->conf = conf;
	r->resolver = (struct resolver *)0x1234;
	r->server = NULL;
	r->basereq = NULL;
	r->L = L;
	r->config.traceback = false;
	r->config.memlimit_kb = 0;
	STUB.loop = loop;
	(void)luaopen_await(L);
	lua_setglobal(L, "await");
	return L;
}

static bool run_chunk(lua_State *restrict L, const char *restrict chunk)
{
	if (luaL_loadstring(L, chunk) != LUA_OK) {
		return false;
	}
	return lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK;
}

static void trigger_resolve_ipv4(const char *restrict ip)
{
	union sockaddr_max addr = { .in = { .sin_family = AF_INET } };

	T_CHECK(STUB.resolve_query != NULL);
	T_CHECK(inet_pton(AF_INET, ip, &addr.in.sin_addr) == 1);
	STUB.resolve_cb.func(
		STUB.resolve_query, STUB.loop, STUB.resolve_cb.data, &addr, 1);
	free(STUB.resolve_query);
	STUB.resolve_query = NULL;
}

static void trigger_resolve_failure(void)
{
	T_CHECK(STUB.resolve_query != NULL);
	/* the answer is empty when name resolution fails */
	STUB.resolve_cb.func(
		STUB.resolve_query, STUB.loop, STUB.resolve_cb.data, NULL, 0);
	free(STUB.resolve_query);
	STUB.resolve_query = NULL;
}

static void trigger_invoke_success(const char *restrict chunk)
{
	struct string_stream stream;
	struct io_stream *const s = string_stream_open(&stream, chunk);

	T_CHECK(STUB.api_ctx != NULL);
	STUB.api_cb.func(STUB.api_ctx, STUB.loop, STUB.api_cb.data, NULL, 0, s);
	free(STUB.api_ctx);
	STUB.api_ctx = NULL;
}

/* Complete the pending invoke with an api_client-level error, as
 * api_client_finish_errmsg does. errmsg is not NUL-terminated in general, so
 * the length is passed explicitly and await.invoke must honor it. */
static void
trigger_invoke_failure(const char *restrict errmsg, const size_t errlen)
{
	T_CHECK(STUB.api_ctx != NULL);
	STUB.api_cb.func(
		STUB.api_ctx, STUB.loop, STUB.api_cb.data, errmsg, errlen,
		NULL);
	free(STUB.api_ctx);
	STUB.api_ctx = NULL;
}

/* The connected fd handed to the most recent await.forward() commit. */
static int g_committed_fd = -1;

static void mock_forward_commit(
	struct ev_loop *loop, struct ruleset_callback *restrict cb,
	const int fd)
{
	(void)loop;
	(void)cb;
	g_committed_fd = fd;
}

static void trigger_dial_success(const int fd)
{
	T_CHECK(STUB.dial_d != NULL);
	struct dialer *const d = STUB.dial_d;
	STUB.dial_pending = false;
	STUB.dial_d = NULL;
	d->dialed_fd = fd;
	d->finish_cb.func(STUB.loop, d->finish_cb.data, fd);
}

static void trigger_dial_failure(void)
{
	T_CHECK(STUB.dial_d != NULL);
	struct dialer *const d = STUB.dial_d;
	STUB.dial_pending = false;
	STUB.dial_d = NULL;
	d->err = DIALER_ERR_CONNECT;
	d->syserr = ECONNREFUSED;
	d->dialed_fd = -1;
	d->finish_cb.func(STUB.loop, d->finish_cb.data, -1);
}

/* ---- tests ---- */

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - await/yield scheduling and resumption cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(await_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "await");
	T_EXPECT(lua_istable(L, -1));

	const char *const fns[] = { "sleep", "resolve", "invoke", "execute",
				    "forward" };
	for (size_t i = 0; i < ARRAY_SIZE(fns); i++) {
		lua_getfield(L, -1, fns[i]);
		T_EXPECT(lua_isfunction(L, -1));
		lua_pop(L, 1);
	}

	lua_close(L);
}

T_DECLARE_CASE(await_sleep_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* pcall captures the error thrown by AWAIT_CHECK_YIELDABLE */
	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(await.sleep, 0) "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_resolve_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(await.resolve, 'example.com') "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_resolve_rejects_embedded_nul)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	T_CHECK(L != NULL);

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.r_ok, _G.r_err = pcall(await.resolve, "
		   "'example.com'..string.char(0)..'.attacker') "
		   "end) "
		   "return coroutine.resume(co)"));
	lua_getglobal(L, "r_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "r_err");
	const char *const err = lua_tostring(L, -1);
	T_EXPECT(err != NULL);
	if (err != NULL) {
		T_EXPECT(strstr(err, "NUL") != NULL);
	}
	lua_pop(L, 1);
	T_EXPECT(STUB.resolve_query == NULL);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_invoke_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local ok, err = pcall(await.invoke, 'return 1', '127.0.0.1:1') "
		"return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_sleep_real_paths)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "sleep_done",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L,
		"co = coroutine.create(function() await.sleep(0); _G.sleep_done = 'idle' end) "
		"return coroutine.resume(co)"));
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	lua_getglobal(L, "sleep_done");
	T_EXPECT_STREQ(lua_tostring(L, -1), "idle");
	lua_pop(L, 1);

	lua_pushnil(L);
	lua_setglobal(L, "sleep_done");
	T_EXPECT(run_chunk(
		L,
		"co = coroutine.create(function() await.sleep(0.001); _G.sleep_done = 'timer' end) "
		"return coroutine.resume(co)"));
	/* the coroutine armed a 1ms Lua-owned ev_timer; cross its deadline on the
	 * virtual clock and expire it with one non-blocking round, then restore
	 * real time so wait_until drives the resume idle under a live watchdog --
	 * no wall-clock sleep */
	vclock_freeze_now();
	vclock_advance(1.0);
	ev_run(loop, EVRUN_NOWAIT);
	vclock_stop();
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	lua_getglobal(L, "sleep_done");
	T_EXPECT_STREQ(lua_tostring(L, -1), "timer");
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_resolve_real_path)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "resolve_result",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L,
		"co = coroutine.create(function() _G.resolve_result = await.resolve('example.com') end) "
		"return coroutine.resume(co)"));
	trigger_resolve_ipv4("127.0.0.1");
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	lua_getglobal(L, "resolve_result");
	T_EXPECT_STREQ(lua_tostring(L, -1), "127.0.0.1");
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_resolve_failure_returns_nil)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "resolve_done",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "local addr = await.resolve('bad.invalid') "
		   "_G.resolve_done = (addr == nil) and 'nil' or addr end) "
		   "return coroutine.resume(co)"));
	/* resolution failure must not crash; await.resolve returns nil */
	trigger_resolve_failure();
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	lua_getglobal(L, "resolve_done");
	T_EXPECT_STREQ(lua_tostring(L, -1), "nil");
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_invoke_real_path)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "invoke_value",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, fn = await.invoke('return 1', '127.0.0.1:80') "
		   "  _G.invoke_ok = ok "
		   "  if ok then _G.invoke_value = fn() end "
		   "end) "
		   "return coroutine.resume(co)"));
	trigger_invoke_success("return 42");
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	T_CHECK(STUB.req != NULL);
	T_EXPECT_STREQ(STUB.payload, "return 1");
	T_EXPECT_EQ(STUB.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(STUB.req->addr.port, UINT16_C(80));
	lua_getglobal(L, "invoke_ok");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);
	lua_getglobal(L, "invoke_value");
	T_EXPECT_EQ(lua_tointeger(L, -1), 42);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

/*
 * The asynchronous error return: when the api_client callback reports an
 * error, await.invoke resumes as `false, <error>`. Only the synchronous start
 * failure was covered, leaving both this contract and invoke_cb's errlen
 * bookkeeping (whose comment flags a lifetime subtlety) unverified. The error
 * message is deliberately not NUL-terminated at errlen, so a length mix-up
 * over-reads into the trailing sentinel instead of going unnoticed.
 */
T_DECLARE_CASE(await_invoke_reports_async_error)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "invoke_err",
	};
	static const char errmsg[] = "connection refused!TRAILING";
	static const size_t errlen = sizeof("connection refused") - 1;

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, err = await.invoke('return 1', '127.0.0.1:80') "
		   "  _G.invoke_ok = ok "
		   "  _G.invoke_err = err "
		   "end) "
		   "return coroutine.resume(co)"));
	trigger_invoke_failure(errmsg, errlen);
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));

	lua_getglobal(L, "invoke_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	/* exactly the reported bytes, neither truncated nor over-read */
	lua_getglobal(L, "invoke_err");
	T_EXPECT_STREQ(lua_tostring(L, -1), "connection refused");
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

/*
 * The third reply outcome: a body that does not compile. await.invoke must
 * raise the compile error instead of returning a bogus success, and it raises
 * from inside its continuation, after aux_close() and lua_settop() have already
 * emptied the stack -- so the error object has to be built there and survive.
 */
T_DECLARE_CASE(await_invoke_reports_chunk_error)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "invoke_err",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L,
		"co = coroutine.create(function() "
		"  local ok, err = pcall(await.invoke, 'return 1', '127.0.0.1:80') "
		"  _G.invoke_ok = ok "
		"  _G.invoke_err = err "
		"end) "
		"return coroutine.resume(co)"));
	trigger_invoke_success("return (((");
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));

	lua_getglobal(L, "invoke_ok");
	T_EXPECT(lua_isboolean(L, -1));
	/* the pcall caught a raised error */
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "invoke_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	/* the compiler's message, named after the rpc chunk */
	T_EXPECT(strstr(err, "(rpc)") != NULL);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

/*
 * The reply chunk runs in a fresh sandbox _ENV rather than the real globals:
 * a global it assigns must not reach _G, while a global it reads still falls
 * through to _G. That containment is a security-relevant contract of
 * await.invoke, since the chunk is whatever the peer sent.
 */
T_DECLARE_CASE(await_invoke_sandboxes_rpc_chunk)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "invoke_leaked",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, fn = await.invoke('return 1', '127.0.0.1:80') "
		   "  _G.invoke_ok = ok "
		   "  _G.invoke_read = fn() "
		   "  _G.invoke_leaked = (rawget(_G, 'rpc_probe') ~= nil) "
		   "end) "
		   "return coroutine.resume(co)"));
	trigger_invoke_success("rpc_probe = 1 return type(math)");
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));

	lua_getglobal(L, "invoke_ok");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);
	/* reads fall through the sandbox metatable to the real globals */
	lua_getglobal(L, "invoke_read");
	T_EXPECT_STREQ(lua_tostring(L, -1), "table");
	lua_pop(L, 1);
	/* writes stay in the sandbox */
	lua_getglobal(L, "invoke_leaked");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

/*
 * Regression: await.invoke with no address argument at all used to abort
 * the whole process via ASSERT(n > 0) in aux_todialreq instead of raising
 * a catchable Lua error. The invalid-address check runs synchronously
 * before any yield, so no dial stub/trigger is needed here.
 */
T_DECLARE_CASE(await_invoke_without_address_raises_error)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok = pcall(await.invoke, 'return 1') "
		   "  _G.invoke_pcall_ok = ok "
		   "end) "
		   "return coroutine.resume(co)"));
	lua_getglobal(L, "invoke_pcall_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

T_DECLARE_CASE(await_execute_fork_failure_cleans_up)
{
	struct config conf = { .resolve_pf = PF_UNSPEC };
	struct ruleset r = { 0 };
	struct ev_loop *loop = EV_DEFAULT;
	lua_State *L = new_ruleset_lua(&r, &conf, loop);
	reset_stub_state();
	g_fork_fail = true;
	g_fork_calls = 0;
	/* Never deliver a signal if a cleanup regression invents a target. */
	g_kill_deliver = false;
	const bool ran = run_chunk(
		L, "co = coroutine.create(function() "
		   "_G.x_ok, _G.x_err = pcall(await.execute, 'exit 0') end) "
		   "return coroutine.resume(co)");
	g_fork_fail = false;
	T_EXPECT(ran);
	T_EXPECT_EQ(g_fork_calls, 1);
	lua_getglobal(L, "x_ok");
	T_EXPECT(!lua_toboolean(L, -1));
	lua_pop(L, 1);
	lua_getglobal(L, "x_err");
	T_EXPECT_STREQ(lua_tostring(L, -1), strerror(EAGAIN));
	lua_pop(L, 1);
	aux_getregtable(L, RIDX_AWAIT_CONTEXT);
	lua_pushnil(L);
	T_EXPECT(lua_next(L, -2) == 0);
	lua_pop(L, 1);
	T_EXPECT_EQ(ev_pending_count(loop), 0);
	T_EXPECT_EQ(ev_run(loop, EVRUN_NOWAIT), 0);
	T_EXPECT_EQ(g_kill_count, 0);
#if HAVE_LUA_TOCLOSE
	T_EXPECT(run_chunk(L, "assert(coroutine.close(co)); co=nil"));
#else
	T_EXPECT(run_chunk(L, "co=nil"));
#endif
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(g_kill_count, 0);
	g_kill_deliver = true;
	/* The disarmed operation must still start and complete normally. */
	T_EXPECT(run_chunk(
		L,
		"co=coroutine.create(function() local ok,kind,code=await.execute('exit 0') "
		"assert(ok and kind=='exit' and code==0); _G.x_done=true end) "
		"assert(coroutine.resume(co))"));
	struct lua_global_pred pred = { .L = L, .name = "x_done" };
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	T_EXPECT_EQ(g_fork_calls, 2);
	T_EXPECT_EQ(g_kill_count, 0);
	lua_close(L);
	T_EXPECT_EQ(g_kill_count, 0);
	kill_trace_reset();
}

T_DECLARE_CASE(await_execute_reports_exit_status)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "exec_kind",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, kind, code = await.execute('exit 3') "
		   "  _G.exec_ok = ok ~= nil "
		   "  _G.exec_kind = kind "
		   "  _G.exec_code = code "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, 1.0));
	lua_getglobal(L, "exec_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "exec_kind");
	T_EXPECT_STREQ(lua_tostring(L, -1), "exit");
	lua_pop(L, 1);
	lua_getglobal(L, "exec_code");
	T_EXPECT_EQ(lua_tointeger(L, -1), 3);
	lua_pop(L, 1);

	lua_close(L);
}

/* The common case: a command exiting 0 returns true, "exit", 0. Only the
 * failure sub-branches (non-zero exit, signal) were covered, so a regression
 * flipping this boolean would have passed. */
T_DECLARE_CASE(await_execute_reports_success)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "exec_kind",
	};

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, kind, code = await.execute('exit 0') "
		   "  _G.exec_ok = ok "
		   "  _G.exec_kind = kind "
		   "  _G.exec_code = code "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, 1.0));
	/* true, not merely truthy: the failure paths return nil here */
	lua_getglobal(L, "exec_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);
	lua_getglobal(L, "exec_kind");
	T_EXPECT_STREQ(lua_tostring(L, -1), "exit");
	lua_pop(L, 1);
	lua_getglobal(L, "exec_code");
	T_EXPECT_EQ(lua_tointeger(L, -1), 0);
	lua_pop(L, 1);

	lua_close(L);
}

T_DECLARE_CASE(await_forward_commits_on_success)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.fwd_ok = await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	/* resume: await.forward() starts the dial and yields */
	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending);

	/* complete the dial; the coroutine commits and finishes synchronously */
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
	trigger_dial_success(fd);

	T_EXPECT_EQ(g_committed_fd, fd);
	T_EXPECT_EQ(mock_state.cb, NULL); /* await.forward() cleared it */
	lua_getglobal(L, "fwd_ok");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);

	socket_close(fd);
	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_forward_reports_dial_failure)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.fwd_ok, _G.fwd_err = await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending);
	trigger_dial_failure();

	T_EXPECT_EQ(g_committed_fd, -1); /* never committed */
	/* the session callback is left intact so the caller may retry */
	T_EXPECT(mock_state.cb == &mock_cb);
	lua_getglobal(L, "fwd_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0); /* false */
	lua_pop(L, 1);
	lua_getglobal(L, "fwd_err");
	T_CHECK(lua_tostring(L, -1) != NULL); /* error string */
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

/*
 * The client went away while the dial was still in flight, so ruleset_cancel()
 * cleared state->cb: the completed dial must be reported as a cancelled
 * request rather than committed to a torn-down session, and the descriptor it
 * connected must be dropped -- await_forward_close() is its only owner left,
 * because this arm deliberately does not reset ud->fd.
 */
T_DECLARE_CASE(await_forward_reports_cancelled_request)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.fwd_ok, _G.fwd_err = await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending);

	/* the session is torn down while the dial is pending */
	mock_state.cb = NULL;
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
	trigger_dial_success(fd);

	T_EXPECT_EQ(g_committed_fd, -1); /* never committed */
	lua_getglobal(L, "fwd_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0); /* false, not nil */
	lua_pop(L, 1);
	lua_getglobal(L, "fwd_err");
	T_EXPECT_STREQ(lua_tostring(L, -1), "request cancelled");
	lua_pop(L, 1);
	/* the connected descriptor is closed, not leaked */
	const int fdflags = fcntl(fd, F_GETFD);
	const int err = (fdflags == -1) ? errno : 0;
	T_EXPECT(fdflags == -1);
	T_EXPECT_EQ(err, EBADF);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_forward_rejects_outside_request)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	/* no forward context registered: await.forward() must raise */
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  return pcall(await.forward, '1.2.3.4:80') "
		   "end) "
		   "local _, ok, err = coroutine.resume(co) "
		   "_G.f_ok, _G.f_err = ok, err"));
	lua_getglobal(L, "f_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "f_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "ruleset request") != NULL);
	lua_pop(L, 1);
	T_EXPECT(!STUB.dial_pending); /* never dialed */

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_forward_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* AWAIT_CHECK_YIELDABLE rejects the call before any dial is attempted */
	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(await.forward, '1.2.3.4:80') "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

/* A committed forward consumes the session callback, so a second
 * await.forward in the same request must raise instead of dialing again. */
T_DECLARE_CASE(await_forward_rejects_after_commit)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.fwd_ok = await.forward('1.2.3.4:80') "
		   "  _G.again_ok, _G.again_err = "
		   "    pcall(await.forward, '1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending);
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);
	trigger_dial_success(fd);

	T_EXPECT_EQ(g_committed_fd, fd);
	T_EXPECT_EQ(mock_state.cb, NULL);
	T_EXPECT(!STUB.dial_pending); /* the second call never dialed */
	lua_getglobal(L, "fwd_ok");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);
	lua_getglobal(L, "again_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "again_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not forwardable") != NULL);
	lua_pop(L, 1);

	socket_close(fd);
	lua_close(L);
	ev_loop_destroy(loop);
}

/* A request context whose callback has no forward hook cannot be forwarded
 * either: the call raises before any dial. */
T_DECLARE_CASE(await_forward_rejects_callback_without_forward)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.f_ok, _G.f_err = pcall(await.forward, '1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_EXPECT(!STUB.dial_pending);
	T_EXPECT(mock_state.cb == &mock_cb);
	lua_getglobal(L, "f_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "f_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not forwardable") != NULL);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

/* await.forward() and await.forward(nil) reject the request: each returns a
 * single nil without yielding, dials nothing and leaves the session callback in
 * place for the handler to use. */
T_DECLARE_CASE(await_forward_rejects_nil_address)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	const int live = g_dialreq_live;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local none = table.pack(await.forward()) "
		   "  local null = table.pack(await.forward(nil)) "
		   "  _G.none_n, _G.none_v = none.n, none[1] "
		   "  _G.null_n, _G.null_v = null.n, null[1] "
		   "  _G.done = true "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	lua_getglobal(L, "done");
	T_EXPECT(lua_toboolean(L, -1) != 0); /* finished without yielding */
	lua_pop(L, 1);
	T_EXPECT(!STUB.dial_pending);
	T_EXPECT_EQ(g_committed_fd, -1);
	T_EXPECT(mock_state.cb == &mock_cb);
	T_EXPECT_EQ(g_dialreq_live, live);
	lua_getglobal(L, "none_n");
	T_EXPECT_EQ(lua_tointeger(L, -1), 1);
	lua_pop(L, 1);
	lua_getglobal(L, "none_v");
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 1);
	lua_getglobal(L, "null_n");
	T_EXPECT_EQ(lua_tointeger(L, -1), 1);
	lua_pop(L, 1);
	lua_getglobal(L, "null_v");
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

/* An address that does not parse raises "invalid address" synchronously: no
 * dial starts, the request stays forwardable and no dialreq is left behind. */
T_DECLARE_CASE(await_forward_raises_on_invalid_address)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	const int live = g_dialreq_live;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.f_ok, _G.f_err = pcall(await.forward, 'bogus') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_EXPECT(!STUB.dial_pending);
	T_EXPECT_EQ(g_committed_fd, -1);
	T_EXPECT(mock_state.cb == &mock_cb);
	T_EXPECT_EQ(g_dialreq_live, live);
	lua_getglobal(L, "f_ok");
	T_EXPECT(lua_isboolean(L, -1));
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "f_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, ERR_INVALID_ADDR) != NULL);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_execute_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* AWAIT_CHECK_YIELDABLE rejects the call before fork() runs */
	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(await.execute, 'true') "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_sleep_rejects_bad_argument)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	/* negative, non-finite and out-of-range durations fail luaL_argcheck
	 * synchronously, before any timer is started */
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.s_neg, _G.s_err = pcall(await.sleep, -1) "
		   "  _G.s_inf = pcall(await.sleep, 1/0) "
		   "  _G.s_nan = pcall(await.sleep, 0/0) "
		   "  _G.s_big = pcall(await.sleep, 2e9) "
		   "end) "
		   "return coroutine.resume(co)"));
	lua_getglobal(L, "s_neg");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "s_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	/* the message states the actual constraint, not "(null)" */
	T_EXPECT(strstr(err, "finite") != NULL);
	lua_pop(L, 1);
	const char *const names[] = { "s_inf", "s_nan", "s_big" };
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		lua_getglobal(L, names[i]);
		T_EXPECT(lua_toboolean(L, -1) == 0);
		lua_pop(L, 1);
	}

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_resolve_reports_start_failure)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	STUB.resolve_start_ok = false;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.r_ok, _G.r_err = pcall(await.resolve, 'example.com') "
		   "end) "
		   "return coroutine.resume(co)"));
	lua_getglobal(L, "r_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "r_err");
	T_CHECK(lua_tostring(L, -1) != NULL);
	lua_pop(L, 1);
	/* nothing was started, so nothing is cancelled */
	T_EXPECT(!STUB.resolve_cancelled);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_invoke_reports_start_failure)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	STUB.api_start_ok = false;
	T_EXPECT(run_chunk(
		L,
		"co = coroutine.create(function() "
		"  _G.i_ok, _G.i_err = pcall(await.invoke, 'return 1', '127.0.0.1:80') "
		"end) "
		"return coroutine.resume(co)"));
	lua_getglobal(L, "i_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "i_err");
	T_CHECK(lua_tostring(L, -1) != NULL);
	lua_pop(L, 1);
	T_EXPECT(!STUB.api_cancelled);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_forward_reports_timeout)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
		/* A zero timeout arms the forward deadline to fire on the next
		 * event-loop iteration (the dial is already issued and pending by
		 * then), so the "timeout" result is reached without a real wait. */
		.timeout = 0,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };
	struct lua_global_pred pred = {
		.L = L,
		.name = "fwd_err",
	};

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.fwd_ok, _G.fwd_err = await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending);
	/* no dial callback ever fires: the handshake timeout must resume the
	 * routine with the distinct "timeout" error */
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, TEST_WAIT_SEC));
	T_EXPECT(STUB.dial_cancelled); /* the pending dial was cancelled */
	T_EXPECT(!STUB.dial_pending);
	T_EXPECT_EQ(g_committed_fd, -1);
	lua_getglobal(L, "fwd_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "fwd_err");
	T_EXPECT_STREQ(lua_tostring(L, -1), "timeout");
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_execute_reports_signal)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "exec_kind",
	};

	reset_stub_state();
	/* a child killed by a signal reports (nil, "signal", WTERMSIG) */
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, kind, code = await.execute('kill -9 $$') "
		   "  _G.exec_ok = ok ~= nil "
		   "  _G.exec_kind = kind "
		   "  _G.exec_code = code "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, 1.0));
	lua_getglobal(L, "exec_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "exec_kind");
	T_EXPECT_STREQ(lua_tostring(L, -1), "signal");
	lua_pop(L, 1);
	lua_getglobal(L, "exec_code");
	T_EXPECT_EQ(lua_tointeger(L, -1), SIGKILL);
	lua_pop(L, 1);

	lua_close(L);
}

/* An embedded NUL would truncate the command handed to execv, so await.execute
 * must raise instead of running only the prefix. The check is synchronous
 * (before fork), so no child runs. */
T_DECLARE_CASE(await_execute_rejects_embedded_nul)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  _G.x_ok, _G.x_err = pcall(await.execute, 'a\\0; true') "
		   "end) "
		   "return coroutine.resume(co)"));
	lua_getglobal(L, "x_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "x_err");
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "NUL") != NULL);
	lua_pop(L, 1);

	lua_close(L);
	ev_loop_destroy(loop);
}

/* The daemon ignores SIGPIPE, and an ignored disposition survives execv(), so
 * the child must restore the default before exec: a command signalling itself
 * with SIGPIPE is then killed by it instead of exiting 0. */
T_DECLARE_CASE(await_execute_restores_default_sigpipe)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "exec_kind",
	};
	const struct sigaction ign = { .sa_handler = SIG_IGN };
	struct sigaction old;

	reset_stub_state();
	T_CHECK(sigaction(SIGPIPE, &ign, &old) == 0);
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  local ok, kind, code = await.execute('kill -PIPE $$') "
		   "  _G.exec_ok = ok ~= nil "
		   "  _G.exec_kind = kind "
		   "  _G.exec_code = code "
		   "end) "
		   "return coroutine.resume(co)"));
	const bool finished = wait_until(loop, global_is_non_nil, &pred, 1.0);
	T_CHECK(sigaction(SIGPIPE, &old, NULL) == 0);
	T_EXPECT(finished);
	lua_getglobal(L, "exec_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "exec_kind");
	T_EXPECT_STREQ(lua_tostring(L, -1), "signal");
	lua_pop(L, 1);
	lua_getglobal(L, "exec_code");
	T_EXPECT_EQ(lua_tointeger(L, -1), SIGPIPE);
	lua_pop(L, 1);

	lua_close(L);
}

#if WITH_CLOSE_RANGE
/* A descriptor the daemon holds without FD_CLOEXEC must not reach the child:
 * redirecting to it from the spawned shell fails, so the command exits
 * non-zero. */
T_DECLARE_CASE(await_execute_closes_inherited_fds)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct lua_global_pred pred = {
		.L = L,
		.name = "exec_kind",
	};

	reset_stub_state();
	const int fd = open("/dev/null", O_WRONLY);
	T_CHECK(fd > STDERR_FILENO);
	/* the shell only portably redirects a single-digit descriptor */
	T_CHECK(fd <= 9);
	T_CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0);
	char chunk[256];
	const int len = snprintf(
		chunk, sizeof(chunk),
		"co = coroutine.create(function() "
		"  local ok, kind, code = "
		"    await.execute('exec 2>/dev/null; : >&%d') "
		"  _G.exec_ok = ok ~= nil "
		"  _G.exec_kind = kind "
		"  _G.exec_code = code "
		"end) "
		"return coroutine.resume(co)",
		fd);
	T_CHECK(len > 0 && (size_t)len < sizeof(chunk));
	T_EXPECT(run_chunk(L, chunk));
	T_EXPECT(wait_until(loop, global_is_non_nil, &pred, 1.0));
	lua_getglobal(L, "exec_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);
	lua_getglobal(L, "exec_kind");
	T_EXPECT_STREQ(lua_tostring(L, -1), "exit");
	lua_pop(L, 1);
	lua_getglobal(L, "exec_code");
	T_EXPECT(lua_tointeger(L, -1) != 0);
	lua_pop(L, 1);

	(void)close(fd);
	lua_close(L);
}
#endif /* WITH_CLOSE_RANGE */

/*
 * Regression (issue #19): a Lua OOM raised in the window between aux_todialreq
 * building the dialreq and its ownership transfer must not leak the dialreq.
 * The dialreq_new stub arms an allocator failure right after building req; the
 * failure lands on the first following Lua allocation -- the await
 * lua_newuserdata, while req is still an unowned C local, in the buggy code;
 * pin_context, once req is already owned, in the fixed code. The failure is
 * armed twice because Lua runs an emergency GC and retries a failed allocation
 * once before raising LUA_ERRMEM; the GC is stopped so no incidental collection
 * spends the budget elsewhere. After the routine unwinds and finalizers run, no
 * dialreq may remain unaccounted for.
 */
T_DECLARE_CASE(await_invoke_oom_does_not_leak_dialreq)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	g_dialreq_live = 0;
	/* keep aux_getruleset working: preserve the ruleset as the allocator ud */
	lua_setallocf(L, test_failing_alloc, &r);
	/* stop the GC so the injected failure lands on the target allocation,
	 * not on an incidental collection */
	lua_gc(L, LUA_GCSTOP, 0);
	g_oom_arm_on_dialreq = true;

	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.invoke('return 1', '1.2.3.4:80') "
		   "end) "
		   "_G.resume_ok = coroutine.resume(co) "
		   "co = nil"));
	g_oom_arm_on_dialreq = false;
	g_oom_fail_count = 0;
	lua_gc(L, LUA_GCRESTART, 0);

	/* the injected OOM made await.invoke raise, so the resume reported false */
	lua_getglobal(L, "resume_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);

	/* finalize the abandoned coroutine/userdata (the 5.3 __gc path), then
	 * free any dialreq legitimately owned by the started request */
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	reset_stub_state();
	T_EXPECT_EQ(g_dialreq_live, 0);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

T_DECLARE_CASE(await_forward_oom_does_not_leak_dialreq)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_dialreq_live = 0;
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	T_CHECK(co != NULL);
	aux_setforward(L, co, &mock_state);

	lua_setallocf(L, test_failing_alloc, &r);
	lua_gc(L, LUA_GCSTOP, 0);
	g_oom_arm_on_dialreq = true;

	T_EXPECT(run_chunk(
		L, "_G.resume_ok = coroutine.resume(co) "
		   "co = nil"));
	g_oom_arm_on_dialreq = false;
	g_oom_fail_count = 0;
	lua_gc(L, LUA_GCRESTART, 0);

	lua_getglobal(L, "resume_ok");
	T_EXPECT(lua_toboolean(L, -1) == 0);
	lua_pop(L, 1);

	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	reset_stub_state();
	T_EXPECT_EQ(g_dialreq_live, 0);
	T_EXPECT_EQ(g_committed_fd, -1); /* never committed */

	lua_close(L);
	ev_loop_destroy(loop);
	reset_stub_state();
}

#if HAVE_LUA_TOCLOSE
/*
 * The module's __close/__gc design exists to cancel a pending async op when
 * its coroutine is abandoned. coroutine.close() runs the to-be-closed
 * handler; each of these asserts the matching cancel path fires.
 */
T_DECLARE_CASE(await_resolve_abandoned_cancels_query)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.resolve('example.com') "
		   "end) "
		   "return coroutine.resume(co)"));
	T_CHECK(STUB.resolve_query != NULL); /* yielded with a pending query */

	T_EXPECT(run_chunk(L, "return coroutine.close(co)"));
	T_EXPECT(STUB.resolve_cancelled);
	T_EXPECT(STUB.resolve_query == NULL);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_invoke_abandoned_cancels_request)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.invoke('return 1', '127.0.0.1:80') "
		   "end) "
		   "return coroutine.resume(co)"));
	T_CHECK(STUB.api_ctx != NULL); /* yielded with a pending request */

	T_EXPECT(run_chunk(L, "return coroutine.close(co)"));
	T_EXPECT(STUB.api_cancelled);
	T_EXPECT(STUB.api_ctx == NULL);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(await_forward_abandoned_cancels_dial)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	struct ruleset_callback mock_cb = { 0 };
	mock_cb.forward = mock_forward_commit;
	struct ruleset_state mock_state = { .cb = &mock_cb };

	reset_stub_state();
	g_committed_fd = -1;
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.forward('1.2.3.4:80') "
		   "end)"));
	lua_getglobal(L, "co");
	lua_State *const co = lua_tothread(L, -1);
	lua_pop(L, 1);
	aux_setforward(L, co, &mock_state);

	T_EXPECT(run_chunk(L, "return coroutine.resume(co)"));
	T_CHECK(STUB.dial_pending); /* yielded with a pending dial */

	T_EXPECT(run_chunk(L, "return coroutine.close(co)"));
	T_EXPECT(STUB.dial_cancelled);
	T_EXPECT(!STUB.dial_pending);
	T_EXPECT_EQ(g_committed_fd, -1); /* nothing committed */

	lua_close(L);
	ev_loop_destroy(loop);
}

/* await.sleep arms a Lua-owned ev_timer; closing the suspended coroutine must
 * run await_sleep_close (ev_timer_stop + ev_idle_stop) so a later timer
 * expiry cannot fire a callback into the collected userdata. */
T_DECLARE_CASE(await_sleep_abandoned_stops_timer)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	/* a long sleep, so the timer is still pending when the coroutine closes */
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.sleep(30) "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(run_chunk(L, "return coroutine.status(co)"));
	T_EXPECT_STREQ(lua_tostring(L, -1), "suspended");
	lua_pop(L, 1);

	/* coroutine.close runs await_sleep_close */
	T_EXPECT(run_chunk(L, "return coroutine.close(co)"));
	T_EXPECT(lua_toboolean(L, -1));
	lua_pop(L, 1);
	T_EXPECT(run_chunk(L, "return coroutine.status(co)"));
	T_EXPECT_STREQ(lua_tostring(L, -1), "dead");
	lua_pop(L, 1);

	/* Drop and collect the coroutine and its sleep userdata; a regression that
	 * left the timer armed would leave libev holding a freed ev_timer. */
	T_EXPECT(run_chunk(L, "co = nil"));
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);

	/* Crossing the (stopped) timer's deadline must stay quiet -- if it were
	 * still armed, firing it would dereference the collected userdata. */
	vclock_freeze_now();
	vclock_advance(60.0);
	ev_run(loop, EVRUN_NOWAIT);
	vclock_stop();

	lua_close(L);
	ev_loop_destroy(loop);
}

/* The close handler signals the child's process group first, then the child
 * itself, both with SIGKILL. */
T_DECLARE_SUBCASE(expect_sigkill_pair, const pid_t child)
{
	T_EXPECT_EQ(g_kill_count, 2);
	T_EXPECT_EQ(g_kill_calls[0].sig, SIGKILL);
	T_EXPECT_EQ(g_kill_calls[1].sig, SIGKILL);
	T_EXPECT_EQ(g_kill_calls[0].pid, -child);
	T_EXPECT_EQ(g_kill_calls[1].pid, child);
}

/* await.execute forks a real child, so the abandon path (await_execute_close:
 * ev_child_stop + SIGKILL) is exercised only here. Closing the suspended
 * coroutine must run that handler cleanly and leave the coroutine dead.
 * EV_DEFAULT is required for ev_child. */
T_DECLARE_CASE(await_execute_abandoned_stops_child)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_stub_state();
	/* drain anything a prior case left unreaped, so the waitpid() below can
	 * only see the child this case forks */
	while (waitpid(-1, NULL, WNOHANG) > 0) {
	}
	/* A command that would outlive the test unless the child is killed. It
	 * execs in place so the child's session is the single process the kill
	 * trace's sigqueue() delivery reaches. */
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.execute('exec sleep 30') "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(run_chunk(L, "return coroutine.status(co)"));
	T_EXPECT_STREQ(lua_tostring(L, -1), "suspended");
	lua_pop(L, 1);

	/* coroutine.close runs await_execute_close */
	T_EXPECT(run_chunk(L, "return coroutine.close(co)"));
	T_EXPECT(lua_toboolean(L, -1));
	lua_pop(L, 1);
	T_EXPECT(run_chunk(L, "return coroutine.status(co)"));
	T_EXPECT_STREQ(lua_tostring(L, -1), "dead");

	/* A dead coroutine is not enough: the child must actually be gone. The
	 * close path signals it, so reaping it is bounded by SIGKILL delivery --
	 * the poll only covers the child not having been scheduled yet, and a
	 * child that survives (the signal missing it while it is still between
	 * fork() and setsid()) fails here instead of running to completion. */
	int wstatus = 0;
	pid_t child = 0;
	for (int i = 0; i < 1000 && child == 0; i++) {
		child = waitpid(-1, &wstatus, WNOHANG);
		if (child == 0) {
			const struct timespec delay = { .tv_nsec = 1000000 };
			(void)nanosleep(&delay, NULL);
		}
	}
	T_EXPECT(child > 0);
	T_EXPECT(WIFSIGNALED(wstatus));
	T_EXPECT_EQ(WTERMSIG(wstatus), SIGKILL);
	T_CALL_SUBCASE(expect_sigkill_pair, child);

	lua_close(L);
}

/* Abandon the coroutine from inside the window where libev has already reaped
 * the child but has not dispatched its watcher yet. libev bumps every child
 * watcher it feeds to EV_MAXPRI and invokes them newest-fed-first, so a
 * wildcard watcher started before await.execute's own is fed last and
 * therefore runs while await.execute's watcher is still pending -- exactly the
 * state await_execute_close() reads through ev_is_pending(). Recording how many
 * events are pending at that moment lets a round with an await.execute watcher
 * be told from a calibration round without one, so the case cannot pass
 * vacuously if that invocation order ever changes. */
struct reaped_probe {
	/* the Lua state whose global `co` to close, or NULL to close nothing */
	lua_State *L;
	pid_t rpid;
	unsigned int pending;
	bool fired;
	bool closed;
};

static struct reaped_probe REAPED_PROBE;

static void
reaped_probe_cb(struct ev_loop *loop, ev_child *watcher, const int revents)
{
	(void)revents;
	ev_child_stop(loop, watcher);
	REAPED_PROBE.rpid = watcher->rpid;
	REAPED_PROBE.pending = ev_pending_count(loop);
	if (REAPED_PROBE.L != NULL) {
		REAPED_PROBE.closed =
			run_chunk(REAPED_PROBE.L, "return coroutine.close(co)");
	}
	REAPED_PROBE.fired = true;
}

static bool reaped_probe_fired(void *data)
{
	(void)data;
	return REAPED_PROBE.fired;
}

/* Run one round of the probe: reap a child through libev and report what the
 * probe observed. */
static void
run_reaped_probe(struct ev_loop *loop, ev_child *restrict w_probe, lua_State *L)
{
	REAPED_PROBE = (struct reaped_probe){ .L = L };
	ev_child_init(w_probe, reaped_probe_cb, 0, 0);
	ev_child_start(loop, w_probe);
}

/*
 * await_execute_close() is installed as both __close and __gc, so it runs more
 * than once for the same userdata. Closing it in the reaped-but-undispatched
 * window must not signal -- the pid is freed and may already name an unrelated
 * process -- and must leave nothing for a later __gc pass to signal either.
 */
T_DECLARE_CASE(await_execute_close_is_idempotent)
{
	struct config conf = {
		.resolve_pf = PF_UNSPEC,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = EV_DEFAULT;
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);
	ev_child w_probe;

	reset_stub_state();
	/* record what would be signalled without signalling it: the pid under
	 * test is already reaped, so delivery would reach whatever recycled it */
	g_kill_deliver = false;
	/* drain anything a prior case left unreaped, so the probe below can only
	 * see the children this case forks */
	while (waitpid(-1, NULL, WNOHANG) > 0) {
	}

	/* calibration: a child no await.execute watcher is waiting on */
	const pid_t bare = fork();
	if (bare == 0) {
		_exit(EXIT_SUCCESS);
	}
	T_CHECK(bare > 0);
	run_reaped_probe(loop, &w_probe, NULL);
	T_EXPECT(wait_until(loop, reaped_probe_fired, NULL, 1.0));
	ev_child_stop(loop, &w_probe);
	T_EXPECT_EQ(REAPED_PROBE.rpid, bare);
	const unsigned int pending_baseline = REAPED_PROBE.pending;

	run_reaped_probe(loop, &w_probe, L);
	T_EXPECT(run_chunk(
		L, "co = coroutine.create(function() "
		   "  await.execute('exit 0') "
		   "end) "
		   "return coroutine.resume(co)"));
	T_EXPECT(wait_until(loop, reaped_probe_fired, NULL, 1.0));
	ev_child_stop(loop, &w_probe);

	T_EXPECT(REAPED_PROBE.closed);
	T_EXPECT(REAPED_PROBE.rpid > 0);
	/* one more watcher pending than the calibration round: await.execute's
	 * own, still undispatched, i.e. the window really was entered */
	T_EXPECT_EQ(REAPED_PROBE.pending, pending_baseline + 1);
	T_EXPECT_EQ(g_kill_count, 0);

	/* the __gc pass must find nothing left to signal */
	T_EXPECT(run_chunk(L, "co = nil"));
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(g_kill_count, 0);

	lua_close(L);
	T_EXPECT_EQ(g_kill_count, 0);
	kill_trace_reset();
}
#endif /* HAVE_LUA_TOCLOSE */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(await_module_opens),
	T_CASE(await_sleep_rejects_non_coroutine),
	T_CASE(await_resolve_rejects_non_coroutine),
	T_CASE(await_resolve_rejects_embedded_nul),
	T_CASE(await_invoke_rejects_non_coroutine),
	T_CASE(await_sleep_real_paths),
	T_CASE(await_resolve_real_path),
	T_CASE(await_resolve_failure_returns_nil),
	T_CASE(await_invoke_real_path),
	T_CASE(await_invoke_reports_async_error),
	T_CASE(await_invoke_reports_chunk_error),
	T_CASE(await_invoke_sandboxes_rpc_chunk),
	T_CASE(await_invoke_without_address_raises_error),
	T_CASE(await_execute_fork_failure_cleans_up),
	T_CASE(await_execute_reports_success),
	T_CASE(await_execute_reports_exit_status),
	T_CASE(await_execute_reports_signal),
	T_CASE(await_execute_rejects_embedded_nul),
	T_CASE(await_execute_restores_default_sigpipe),
#if WITH_CLOSE_RANGE
	T_CASE(await_execute_closes_inherited_fds),
#endif /* WITH_CLOSE_RANGE */
	T_CASE(await_forward_commits_on_success),
	T_CASE(await_forward_reports_dial_failure),
	T_CASE(await_forward_reports_timeout),
	T_CASE(await_forward_reports_cancelled_request),
	T_CASE(await_forward_rejects_outside_request),
	T_CASE(await_forward_rejects_non_coroutine),
	T_CASE(await_forward_rejects_after_commit),
	T_CASE(await_forward_rejects_callback_without_forward),
	T_CASE(await_forward_rejects_nil_address),
	T_CASE(await_forward_raises_on_invalid_address),
	T_CASE(await_execute_rejects_non_coroutine),
	T_CASE(await_sleep_rejects_bad_argument),
	T_CASE(await_resolve_reports_start_failure),
	T_CASE(await_invoke_reports_start_failure),
	T_CASE(await_invoke_oom_does_not_leak_dialreq),
	T_CASE(await_forward_oom_does_not_leak_dialreq),
#if HAVE_LUA_TOCLOSE
	T_CASE(await_sleep_abandoned_stops_timer),
	T_CASE(await_resolve_abandoned_cancels_query),
	T_CASE(await_invoke_abandoned_cancels_request),
	T_CASE(await_forward_abandoned_cancels_dial),
	T_CASE(await_execute_abandoned_stops_child),
	T_CASE(await_execute_close_is_idempotent),
#endif /* HAVE_LUA_TOCLOSE */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
