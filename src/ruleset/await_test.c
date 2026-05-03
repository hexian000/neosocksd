/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/await.h"

#include "ruleset/base.h"

#include "api_client.h"
#include "conf.h"
#include "dialer.h"
#include "io/stream.h"
#include "resolver.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <arpa/inet.h>
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

const char *proxy_protocol_str[PROTO_MAX] = {
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
	struct resolver *resolver)
{
	(void)conf;
	(void)resolver;
	if (!STUB.api_start_ok) {
		return false;
	}
	STUB.loop = loop;
	STUB.api_ctx = malloc(1);
	if (STUB.api_ctx == NULL) {
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
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(STUB.resolve_query != NULL);
	T_CHECK(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
	STUB.resolve_cb.func(
		STUB.resolve_query, STUB.loop, STUB.resolve_cb.data,
		(const struct sockaddr *)&sa);
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

/* ---- tests ---- */

T_DECLARE_CASE(await_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "await");
	T_EXPECT(lua_istable(L, -1));

	const char *const fns[] = { "sleep", "resolve", "invoke", "execute" };
	for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, await_module_opens);
	T_RUN_CASE(t, await_sleep_rejects_non_coroutine);
	T_RUN_CASE(t, await_resolve_rejects_non_coroutine);
	T_RUN_CASE(t, await_invoke_rejects_non_coroutine);
	T_RUN_CASE(t, await_sleep_real_paths);
	T_RUN_CASE(t, await_resolve_real_path);
	T_RUN_CASE(t, await_invoke_real_path);
	T_RUN_CASE(t, await_execute_reports_exit_status);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
