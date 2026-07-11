/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * await_test - white-box unit tests for ruleset/await.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/await.c  module under test
 *   ruleset/base.c   ruleset Lua substrate
 * The dialer/resolver/api_client/server symbols bound by await.c are replaced
 * by the mocks in the mock section below.
 */

#include "ruleset/await.h"

#include "api_client.h"
#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
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
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (dialer, resolver, api_client, server) and
 * shared fixtures.
 * ---------------------------------------------------------------------- */

static const ev_tstamp TEST_WAIT_SEC = 0.128;

struct test_watchdog {
	bool fired;
};

struct string_stream {
	struct stream stream;
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

static const struct stream_vftable string_stream_vftable = {
	.direct_read = string_stream_direct_read,
};

static struct stream *
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
	const struct api_client_cb *restrict cb, const struct config *conf,
	struct resolver *resolver, struct server_stats *restrict stats)
{
	(void)conf;
	(void)resolver;
	(void)stats;
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
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(STUB.resolve_query != NULL);
	T_CHECK(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	STUB.resolve_cb.func(
		STUB.resolve_query, STUB.loop, STUB.resolve_cb.data,
		(const struct sockaddr *)&sa);
	free(STUB.resolve_query);
	STUB.resolve_query = NULL;
}

static void trigger_resolve_failure(void)
{
	T_CHECK(STUB.resolve_query != NULL);
	/* sa is NULL when name resolution fails */
	STUB.resolve_cb.func(
		STUB.resolve_query, STUB.loop, STUB.resolve_cb.data, NULL);
	free(STUB.resolve_query);
	STUB.resolve_query = NULL;
}

static void trigger_invoke_success(const char *restrict chunk)
{
	struct string_stream stream;
	struct stream *const s = string_stream_open(&stream, chunk);

	T_CHECK(STUB.api_ctx != NULL);
	STUB.api_cb.func(STUB.api_ctx, STUB.loop, STUB.api_cb.data, NULL, 0, s);
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
		.timeout = 0.001,
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
	T_CASE(await_invoke_rejects_non_coroutine),
	T_CASE(await_sleep_real_paths),
	T_CASE(await_resolve_real_path),
	T_CASE(await_resolve_failure_returns_nil),
	T_CASE(await_invoke_real_path),
	T_CASE(await_invoke_without_address_raises_error),
	T_CASE(await_execute_reports_exit_status),
	T_CASE(await_execute_reports_signal),
	T_CASE(await_forward_commits_on_success),
	T_CASE(await_forward_reports_dial_failure),
	T_CASE(await_forward_reports_timeout),
	T_CASE(await_forward_rejects_outside_request),
	T_CASE(await_forward_rejects_non_coroutine),
	T_CASE(await_execute_rejects_non_coroutine),
	T_CASE(await_sleep_rejects_bad_argument),
	T_CASE(await_resolve_reports_start_failure),
	T_CASE(await_invoke_reports_start_failure),
#if HAVE_LUA_TOCLOSE
	T_CASE(await_resolve_abandoned_cancels_query),
	T_CASE(await_invoke_abandoned_cancels_request),
	T_CASE(await_forward_abandoned_cancels_dial),
#endif /* HAVE_LUA_TOCLOSE */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
