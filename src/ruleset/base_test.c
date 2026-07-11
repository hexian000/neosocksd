/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * base_test - white-box unit tests for ruleset/base.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/base.c   module under test
 *   util.c           leaf
 *   dialer.c         linked for the symbols bound by the Lua base library
 *   resolver.c       linked for the symbols bound by the Lua base library
 *   version.c        leaf
 * base.c has no stateful collaborator to mock; the mock section only holds
 * shared Lua test fixtures.
 */

#include "ruleset/base.h"

#include "dialer.h"

#include "io/stream.h"
#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (base.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static int g_close_called;
static int test_close(lua_State *restrict L)
{
	(void)L;
	g_close_called++;
	return 0;
}

static int async_finish(lua_State *restrict L)
{
	(void)L;
	return 0;
}

static int async_worker(lua_State *restrict L)
{
	lua_pushinteger(L, 99);
	return 1;
}

static int pcall_push_result(lua_State *restrict L)
{
	lua_pushinteger(L, 7);
	return 1;
}

static int pcall_raise_error(lua_State *restrict L)
{
	lua_pushliteral(L, "boom");
	return lua_error(L);
}

static int
resume_finish(lua_State *restrict L, int status, const lua_KContext ctx)
{
	(void)status;
	(void)ctx;
	lua_pushboolean(L, 1);
	lua_setglobal(L, "resumed");
	return 0;
}

static int resume_yield(lua_State *restrict L)
{
	return lua_yieldk(L, 0, 0, resume_finish);
}

static int getregtable_idle_thunk(lua_State *restrict L)
{
	aux_getregtable(L, RIDX_IDLE_THREAD);
	return 1;
}

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	return L;
}

static lua_State *new_ruleset_lua(struct ruleset *restrict r)
{
	lua_State *restrict L = new_lua();
	lua_Alloc alloc;

	T_CHECK(L != NULL);
	alloc = lua_getallocf(L, NULL);
	lua_setallocf(L, alloc, r);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	aux_newweaktable(L, "k");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	return L;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - auxiliary table/helper and GC integration cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(base_aux_newweaktable_v)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	aux_newweaktable(L, "v");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "v");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_newweaktable_k)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	aux_newweaktable(L, "k");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "k");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_toclose_sets_gc)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	g_close_called = 0;
	(void)lua_newuserdata(L, sizeof(uint_least8_t));
	aux_toclose(L, -1, "test.close.mt", test_close);
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__gc");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(base_aux_close_behavior)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	g_close_called = 0;
	(void)lua_newuserdata(L, sizeof(uint_least8_t));
	aux_toclose(L, -1, "test.close.mt2", test_close);
	aux_close(L, -1);
#if HAVE_LUA_TOCLOSE
	T_EXPECT_EQ(g_close_called, 0);
#else
	T_EXPECT_EQ(g_close_called, 1);
#endif

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_ipv4)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "127.0.0.1");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_ipv6)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	T_CHECK(inet_pton(AF_INET6, "::1", &sa.sin6_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "::1");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_null)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_pushlightuserdata(L, NULL);
	T_EXPECT_EQ(aux_format_addr(L), 0);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_unknown_family)
{
	lua_State *restrict L = new_lua();
	struct sockaddr sa = {
		.sa_family = AF_UNIX,
	};

	T_CHECK(L != NULL);
	lua_pushcfunction(L, aux_format_addr);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(lua_pcall(L, 1, 1, 0), LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "unknown af") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_traceback_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_pushliteral(L, "boom");
	T_EXPECT_EQ(aux_traceback(L), 1);
	const char *restrict s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strstr(s, "boom") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_todialreq_builds_request)
{
	struct ruleset r = { 0 };
	lua_State *restrict L;
	struct dialreq *req;

	r.basereq =
		dialreq_parse("base.example:443", "socks5://127.0.0.1:1080");
	T_CHECK(r.basereq != NULL);
	L = new_ruleset_lua(&r);

	lua_pushstring(L, "example.com:80");
	lua_pushstring(L, "http://127.0.0.2:8080");
	T_EXPECT(aux_todialreq(L, 2));
	req = lua_touserdata(L, -1);
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(req->addr.port, UINT16_C(80));
	T_EXPECT_EQ(req->num_proxy, (size_t)2);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[1].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[1].addr.type, ATYP_INET);
	T_EXPECT_EQ(req->proxy[1].addr.port, UINT16_C(8080));
	dialreq_free(req);
	dialreq_free(r.basereq);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_todialreq_nil_returns_null)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);

	lua_pushnil(L);
	T_EXPECT(aux_todialreq(L, 1));
	T_EXPECT_EQ(lua_touserdata(L, -1), NULL);

	lua_close(L);
}

/* Regression: aux_todialreq must honor its documented [-n, ...] stack effect
 * even on the n > 255 early-out, popping its arguments like every other
 * failure path. */
T_DECLARE_CASE(base_aux_todialreq_overflow_pops_stack)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);

	const int base = lua_gettop(L);
	const int n = 256; /* > 255 */
	T_CHECK(lua_checkstack(L, n + 1));
	for (int i = 0; i < n; i++) {
		lua_pushstring(L, "example.com:80");
	}
	T_EXPECT(!aux_todialreq(L, n));
	T_EXPECT_EQ(lua_gettop(L), base); /* the n arguments must be popped */

	lua_close(L);
}

T_DECLARE_CASE(base_aux_async_reuses_idle_thread)
{
	struct ruleset r = {
		.config.traceback = false,
	};
	lua_State *restrict L = new_ruleset_lua(&r);
	lua_State *co1, *co2;

	co1 = aux_getthread(L);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)1);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	T_EXPECT_EQ(aux_async(co1, L, 0, 1), LUA_YIELD);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);
	lua_settop(L, 0);

	co2 = aux_getthread(L);
	T_EXPECT_EQ(co2, co1);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)1);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_getregtable_rejects_non_table)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);

	/* a non-table registry slot must raise ERR_BAD_REGISTRY */
	lua_pushboolean(L, 1);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);

	lua_pushcfunction(L, getregtable_idle_thunk);
	T_EXPECT_EQ(lua_pcall(L, 0, 1, 0), LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "registry is corrupted") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_forward_context_roundtrip)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);

	/* nothing pinned yet */
	T_EXPECT(aux_getforward(L) == NULL);

	/* set -> get returns the same pointer (keyed by the current thread) */
	int state = 0;
	aux_setforward(L, L, &state);
	T_EXPECT_EQ(aux_getforward(L), &state);

	/* set NULL -> get returns NULL */
	aux_setforward(L, L, NULL);
	T_EXPECT(aux_getforward(L) == NULL);

	lua_close(L);
}

T_DECLARE_CASE(base_ruleset_pcall_success_and_error)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);
	r.L = L;

	/* success path returns true and records one event */
	T_EXPECT(ruleset_pcall(&r, pcall_push_result, 0, 1));
	T_EXPECT_EQ(r.vmstats.num_events, (size_t)1);

	/* error path returns false, records another event, and stows the error
	 * message in RIDX_LASTERROR */
	T_EXPECT(!ruleset_pcall(&r, pcall_raise_error, 0, 0));
	T_EXPECT_EQ(r.vmstats.num_events, (size_t)2);
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	const char *const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "boom") != NULL);
	lua_pop(L, 1);

	lua_close(L);
}

T_DECLARE_CASE(base_ruleset_resume_wakes_coroutine)
{
	struct ruleset r = { 0 };
	lua_State *restrict L = new_ruleset_lua(&r);
	r.L = L;

	/* create a coroutine that yields and pin it in the await context */
	lua_State *const co = lua_newthread(L);
	int ctx_key = 0;
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_pushvalue(L, -2); /* co */
	lua_rawsetp(L, -2, &ctx_key);
	lua_pop(L, 1); /* pop the await-context table; co ref remains */

	lua_pushcfunction(co, resume_yield);
	int nres;
	T_CHECK(lua_resume(co, L, 0, &nres) == LUA_YIELD);
	lua_pop(L,
		1); /* drop the co reference (still kept alive by the table) */

	/* ruleset_resume looks co up by ctx and drives it to completion */
	ruleset_resume(&r, &ctx_key, 0);
	T_EXPECT_EQ(r.vmstats.num_events, (size_t)1);
	lua_getglobal(L, "resumed");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);

	lua_close(L);
}

/*
 * A catastrophic lua_resume failure (here forced by corrupting
 * RIDX_IDLE_THREAD so thread_call_k's re-caching raises after the finish
 * callback runs) must decrement num_thread_active exactly once and clear the
 * abandoned coroutine's forward-context entry.
 */
T_DECLARE_CASE(base_aux_async_catastrophic_failure_cleanup)
{
	struct ruleset r = {
		.config.traceback = false,
	};
	lua_State *restrict L = new_ruleset_lua(&r);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);

	lua_State *const co = aux_getthread(L);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)1);

	/* register a forward context for co, as cfunc_request would */
	int fwd_state = 0;
	aux_setforward(L, co, &fwd_state);

	/* corrupt the idle-thread cache so thread_call_k raises after decrement
	 * point moves; forces the catastrophic-resume path */
	lua_pushboolean(L, 1);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);

	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	const int status = aux_async(co, L, 0, 1);
	T_EXPECT(status != LUA_OK && status != LUA_YIELD);

	/* decremented exactly once (0), not double-counted (SIZE_MAX) */
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);

	lua_settop(L, 0);
	/* the abandoned coroutine's forward-context entry is cleared */
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
	lua_rawgetp(L, -1, co);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);

	lua_close(L);
}

/* A stream that yields a chunk on its first direct_read and then either EOF or
 * a read error, to exercise aux_load()'s mid-stream error handling. */
struct fault_stream {
	struct stream stream;
	const char *text;
	size_t len;
	bool fail;
	int phase;
};

static int fault_stream_direct_read(void *data, const void **buf, size_t *len)
{
	struct fault_stream *const s = data;
	if (s->phase++ == 0) {
		*buf = s->text;
		*len = s->len;
		return 0;
	}
	*buf = NULL;
	*len = 0;
	return s->fail ? -1 : 0; /* -1: a mid-stream read error */
}

static const struct stream_vftable fault_stream_vftable = {
	.direct_read = fault_stream_direct_read,
};

/* Regression: aux_load() must report a mid-stream read error as a load
 * failure, not let lua_load() treat the truncated input as a clean EOF and
 * compile the (valid-prefix) partial chunk. */
T_DECLARE_CASE(base_aux_load_reports_mid_stream_read_error)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* control: a complete chunk with a clean EOF loads successfully */
	struct fault_stream ok = {
		.stream = { .vftable = &fault_stream_vftable, .data = &ok },
		.text = "return 1",
		.len = sizeof("return 1") - 1,
		.fail = false,
		.phase = 0,
	};
	T_EXPECT_EQ(aux_load(L, &ok.stream, "=ok"), LUA_OK);
	lua_settop(L, 0);

	/* a read error after that same valid prefix must fail the load */
	struct fault_stream bad = {
		.stream = { .vftable = &fault_stream_vftable, .data = &bad },
		.text = "return 1",
		.len = sizeof("return 1") - 1,
		.fail = true,
		.phase = 0,
	};
	T_EXPECT(aux_load(L, &bad.stream, "=bad") != LUA_OK);
	lua_settop(L, 0);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(base_aux_newweaktable_v),
	T_CASE(base_aux_newweaktable_k),
	T_CASE(base_aux_toclose_sets_gc),
	T_CASE(base_aux_close_behavior),
	T_CASE(base_aux_format_addr_ipv4),
	T_CASE(base_aux_format_addr_ipv6),
	T_CASE(base_aux_format_addr_null),
	T_CASE(base_aux_format_addr_unknown_family),
	T_CASE(base_aux_traceback_string),
	T_CASE(base_aux_todialreq_builds_request),
	T_CASE(base_aux_todialreq_nil_returns_null),
	T_CASE(base_aux_todialreq_overflow_pops_stack),
	T_CASE(base_aux_async_reuses_idle_thread),
	T_CASE(base_aux_getregtable_rejects_non_table),
	T_CASE(base_aux_forward_context_roundtrip),
	T_CASE(base_ruleset_pcall_success_and_error),
	T_CASE(base_ruleset_resume_wakes_coroutine),
	T_CASE(base_aux_async_catastrophic_failure_cleanup),
	T_CASE(base_aux_load_reports_mid_stream_read_error),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
