/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * base_test - white-box unit tests for ruleset/base.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/base.c   module under test
 *   proto/codec.c    leaf
 *   util.c           leaf
 *   dialer.c         linked for the symbols bound by the Lua base library
 *   resolver.c       linked for the symbols bound by the Lua base library
 *   version.c        leaf
 * The mock section supplies shared Lua fixtures and controlled readings for
 * the clock_gettime calls behind base.c's inline monotonic clock helper.
 */

#include "base.h"

#include "conf.h"
#include "dialer.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures and monotonic clock readings.
 * ---------------------------------------------------------------------- */

#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
static const struct timespec *event_clock;
static size_t event_clock_calls;

int test_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	if (clk_id == CLOCK_MONOTONIC && event_clock != NULL) {
		const size_t i = event_clock_calls++;
		if (i < 2) {
			*tp = event_clock[i];
			return 0;
		}
	}
	return clock_gettime(clk_id, tp);
}

static void set_event_clock(const struct timespec readings[2])
{
	event_clock = readings;
	event_clock_calls = 0;
}

T_DECLARE_SUBCASE(check_event_clock, const size_t expected)
{
	event_clock = NULL;
	T_EXPECT_EQ(event_clock_calls, expected);
}
#endif /* HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC) */

static bool bootstrap_oom;
static bool thread_guard_oom;
static size_t bootstrap_failures;
static lua_Alloc bootstrap_alloc;

static void *
bootstrap_failing_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (nsize > 0 && (ptr == NULL || nsize > osize)) {
		bootstrap_failures++;
		return NULL;
	}
	return bootstrap_alloc(ud, ptr, osize, nsize);
}

void test_base_setfield(lua_State *L, int idx, const char *key)
{
	if (thread_guard_oom && strcmp(key, "__gc") == 0) {
		idx = lua_absindex(L, idx);
		/* Force the finalizer insertion to grow the metatable hash. */
		for (int i = 0; i < 31; i++) {
			char field[32];
			(void)snprintf(
				field, sizeof(field), "fault_padding_%d", i);
			lua_pushboolean(L, 1);
			lua_setfield(L, idx, field);
		}
		void *ud;
		bootstrap_alloc = lua_getallocf(L, &ud);
		lua_setallocf(L, bootstrap_failing_alloc, ud);
	}
	lua_setfield(L, idx, key);
}

#if LUA_VERSION_NUM >= 504
int test_base_resume(lua_State *L, lua_State *from, int nargs, int *nresults)
#else
int test_base_resume(lua_State *L, lua_State *from, int nargs)
#endif
{
	void *ud = NULL;
	if (bootstrap_oom) {
		bootstrap_alloc = lua_getallocf(L, &ud);
		lua_setallocf(L, bootstrap_failing_alloc, ud);
	}
#if LUA_VERSION_NUM >= 504
	const int status = lua_resume(L, from, nargs, nresults);
#else
	const int status = lua_resume(L, from, nargs);
#endif
	if (bootstrap_oom) {
		lua_setallocf(L, bootstrap_alloc, ud);
	}
	return status;
}

static int g_close_called;
static int test_close(lua_State *restrict L)
{
	(void)L;
	g_close_called++;
	return 0;
}

/* thread_call_k dispatches the finish function as finish(ok, results...); this
 * records that contract so a case can assert the dispatch actually happened. */
struct async_finish_record {
	bool called;
	bool ok;
	int nargs;
	lua_Integer result;
};
static struct async_finish_record async_finish_state;

static int async_finish(lua_State *restrict L)
{
	async_finish_state.called = true;
	async_finish_state.nargs = lua_gettop(L);
	async_finish_state.ok = lua_toboolean(L, 1);
	async_finish_state.result = lua_tointeger(L, 2);
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

static int
resume_error_k(lua_State *restrict L, int status, const lua_KContext ctx)
{
	(void)status;
	(void)ctx;
	lua_pushliteral(L, "resume boom");
	return lua_error(L);
}

/* Yields once, then raises on resume so lua_resume returns an error status --
 * the catastrophic-resume path (thread dies without passing through
 * thread_call_k). */
static int resume_yield_then_error(lua_State *restrict L)
{
	return lua_yieldk(L, 0, 0, resume_error_k);
}

static int getregtable_idle_thunk(lua_State *restrict L)
{
	aux_getregtable(L, RIDX_IDLE_THREAD);
	return 1;
}

static void free_request(void *data)
{
	dialreq_free(data);
}

static unsigned lua_close_count;

static void close_lua(void *data)
{
	lua_close(data);
	lua_close_count++;
}

/* Ruleset and allocator userdata below have static storage because Lua
 * finalizers run after a failed case has left its stack frame. */
static lua_State *new_lua(struct testing_ctx *_t_)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	T_CLEANUP(close_lua, L);
	luaL_openlibs(L);
	return L;
}

static lua_State *
new_ruleset_lua(struct testing_ctx *_t_, struct ruleset *restrict r)
{
	lua_State *restrict L = new_lua(_t_);
	lua_Alloc alloc;

	T_CHECK(L != NULL);
	alloc = lua_getallocf(L, NULL);
	lua_setallocf(L, alloc, r);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	aux_newweaktable(L, "k");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	aux_newweaktable(L, "v");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_THREAD_CONTEXT);
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
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	aux_newweaktable(L, "v");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "v");
}

T_DECLARE_CASE(base_aux_newweaktable_k)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	aux_newweaktable(L, "k");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "k");
}

T_DECLARE_CASE(base_aux_toclose_sets_gc)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	g_close_called = 0;
	(void)lua_newuserdata(L, sizeof(uint_least8_t));
	aux_toclose(L, -1, "test.close.mt", test_close);
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__gc");
	T_EXPECT(lua_isfunction(L, -1));
}

static int getthread_thunk(lua_State *L)
{
	(void)aux_getthread(L);
	return 1;
}

T_DECLARE_CASE(base_thread_bootstrap_oom_is_protected)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *L = new_ruleset_lua(_t_, &r);
	lua_pushcfunction(L, getthread_thunk);
	bootstrap_failures = 0;
	bootstrap_oom = true;
	const int status = lua_pcall(L, 0, 1, 0);
	bootstrap_oom = false;
	const size_t active_after_failure = r.vmstats.num_thread_active;
	const char *error = lua_tostring(L, -1);
	const bool memory_error =
		error != NULL && strstr(error, "memory") != NULL;
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_pushcfunction(L, getthread_thunk);
	const int retry = lua_pcall(L, 0, 1, 0);
	const bool yielded =
		retry == LUA_OK && lua_status(lua_tothread(L, -1)) == LUA_YIELD;
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT(bootstrap_failures > 0);
	/* Lua 5.3 rethrows a moved error object as LUA_ERRRUN. */
	T_EXPECT(status == LUA_ERRMEM || status == LUA_ERRRUN);
	T_EXPECT(memory_error);
	T_EXPECT_EQ(active_after_failure, (size_t)0);
	T_EXPECT(yielded);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);
}

T_DECLARE_CASE(base_thread_repairs_incomplete_metatable)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *L = new_ruleset_lua(_t_, &r);
	void *ud;
	lua_Alloc alloc = lua_getallocf(L, &ud);
	lua_pushcfunction(L, getthread_thunk);
	bootstrap_failures = 0;
	thread_guard_oom = true;
	const int first = lua_pcall(L, 0, 1, 0);
	thread_guard_oom = false;
	lua_setallocf(L, alloc, ud);
	lua_settop(L, 0);
	luaL_getmetatable(L, "ruleset_thread");
	T_CHECK(lua_istable(L, -1));
	lua_getfield(L, -1, "__gc");
	const bool incomplete = lua_isnil(L, -1);
	lua_settop(L, 0);
	(void)aux_getthread(L);
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	const size_t active = r.vmstats.num_thread_active;
	T_EXPECT_EQ(first, LUA_ERRMEM);
	T_EXPECT(bootstrap_failures > 0);
	T_EXPECT(incomplete);
	T_EXPECT_EQ(active, (size_t)0);
}

static lua_Alloc guard_alloc;
static size_t guard_allocations;
static size_t guard_fail_after;

static void *
guard_failing_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (nsize > 0 && (ptr == NULL || nsize > osize) &&
	    guard_fail_after > 0 && ++guard_allocations >= guard_fail_after) {
		return NULL;
	}
	return guard_alloc(ud, ptr, osize, nsize);
}

static int guard_close(lua_State *L)
{
	bool *closed = lua_touserdata(L, 1);
	if (!*closed) {
		*closed = true;
		g_close_called++;
	}
	return 0;
}

static int guard_yield(lua_State *L)
{
	bool *closed = lua_newuserdata(L, sizeof(*closed));
	*closed = false;
	aux_toclose(L, -1, "test.oom.guard", guard_close);
	return lua_yield(L, 0);
}

T_DECLARE_CASE(base_guard_oom_retry_finalizes_abandoned_coroutine)
{
	size_t incomplete = 0;
	for (size_t fail = 1; fail <= 16; fail++) {
		lua_State *L = new_lua(_t_);
		T_CHECK(L != NULL);
		void *ud;
		guard_alloc = lua_getallocf(L, &ud);
		lua_setallocf(L, guard_failing_alloc, ud);
		lua_State *co = lua_newthread(L);
		lua_pushcfunction(co, guard_yield);
		guard_allocations = 0;
		guard_fail_after = fail;
		const int first = aux_resume(co, L, 0);
		guard_fail_after = 0;
		luaL_getmetatable(L, "test.oom.guard");
		bool partial = false;
		if (lua_istable(L, -1)) {
			lua_getfield(L, -1, "__gc");
			partial = lua_isnil(L, -1);
		}
		lua_settop(L, 0);
		lua_gc(L, LUA_GCCOLLECT, 0);
		lua_gc(L, LUA_GCCOLLECT, 0);
		g_close_called = 0;
		co = lua_newthread(L);
		lua_pushcfunction(co, guard_yield);
		const int retry = aux_resume(co, L, 0);
		lua_settop(L, 0);
		lua_gc(L, LUA_GCCOLLECT, 0);
		lua_gc(L, LUA_GCCOLLECT, 0);
		if (partial) {
			incomplete++;
			T_EXPECT_EQ(first, LUA_ERRMEM);
			T_EXPECT_EQ(retry, LUA_YIELD);
			T_EXPECT_EQ(g_close_called, 1);
		}
	}
	T_EXPECT(incomplete > 0);
}

T_DECLARE_CASE(base_aux_close_behavior)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(base_aux_format_addr_ipv4)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "127.0.0.1");
}

T_DECLARE_CASE(base_aux_format_addr_ipv6)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	T_CHECK(inet_pton(AF_INET6, "::1", &sa.sin6_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "::1");
}

T_DECLARE_CASE(base_aux_format_addr_null)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	lua_pushlightuserdata(L, NULL);
	T_EXPECT_EQ(aux_format_addr(L), 0);
}

T_DECLARE_CASE(base_aux_format_addr_unknown_family)
{
	lua_State *restrict L = new_lua(_t_);
	struct sockaddr sa = {
		.sa_family = AF_UNIX,
	};

	T_CHECK(L != NULL);
	lua_pushcfunction(L, aux_format_addr);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(lua_pcall(L, 1, 1, 0), LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "unknown af") != NULL);
}

/* Evaluate @p expr for one error object, hand the result to aux_traceback and
 * check the traceback it heads with. The documented stack effect is
 * [-0, +(1|2)]: a rendering that had to be built stays beneath the traceback. */
T_DECLARE_SUBCASE(
	check_traceback, lua_State *restrict L, const char *restrict expr,
	const char *restrict prefix)
{
	lua_settop(L, 0);
	T_CHECK(luaL_loadstring(L, expr) == LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);

	T_EXPECT_EQ(aux_traceback(L), 1);
	const int pushed = lua_gettop(L) - 1;
	T_EXPECT(pushed == 1 || pushed == 2);
	const char *restrict const s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strncmp(s, prefix, strlen(prefix)) == 0);
	T_EXPECT(strstr(s, "stack traceback:") != NULL);

	lua_settop(L, 0);
}

/*
 * The traceback header was formatted from the type name and address for every
 * non-string error object, so the `traceback' configuration replaced a
 * ruleset's own message with "(table: 0x...)" -- less than the same error
 * reports with the configuration off. aux_errmsg renders it now, so every shape
 * heads the traceback with the message it logs either way.
 */
T_DECLARE_CASE(base_aux_traceback_renders_error_object)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_CALL_SUBCASE(
		check_traceback, L, "return 'ruleset:1: boom'",
		"ruleset:1: boom");
	T_CALL_SUBCASE(check_traceback, L, "return 42", "42");
	T_CALL_SUBCASE(check_traceback, L, "return nil", "nil");
	/* an object without __tostring: type and address */
	T_CALL_SUBCASE(check_traceback, L, "return {}", "table: ");
	/* a working __tostring is the message the operator asked for */
	T_CALL_SUBCASE(
		check_traceback, L,
		"return setmetatable({ code = 42 }, { __tostring = "
		"function(self) return 'denied code=' .. self.code end })",
		"denied code=42");
	/* a __tostring that raises, and one that returns a non-string */
	T_CALL_SUBCASE(
		check_traceback, L,
		"return setmetatable({}, { __tostring = function() error('tostring boom') end })",
		"(unprintable table: ");
	T_CALL_SUBCASE(
		check_traceback, L,
		"return setmetatable({}, { __tostring = function() return {} end })",
		"(unprintable table: ");

	/* neosocksd.traceback() is reachable without an error object, where
	 * reading the stack top would reach below the frame */
	lua_settop(L, 0);
	T_EXPECT_EQ(aux_traceback(L), 1);
	T_EXPECT_EQ(lua_gettop(L), 1);
	const char *restrict const s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strstr(s, "(no error object)") == s);
	T_EXPECT(strstr(s, "stack traceback:") != NULL);
}

/*
 * The constraint the rendering has to respect: luaG_errormsg calls the message
 * handler unprotected, so a raise there re-enters the handler until Lua gives
 * up with LUA_ERRERR and replaces the error with "error in error handling".
 * Drive aux_traceback as a real lua_pcall errfunc over an error object whose
 * __tostring raises: the call still reports LUA_ERRRUN and carries both the
 * fallback message and the traceback.
 */
T_DECLARE_CASE(base_aux_traceback_survives_raising_tostring)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	lua_pushcfunction(L, aux_traceback);
	T_CHECK(luaL_loadstring(
			L,
			"error(setmetatable({}, { __tostring = function() error('tostring boom') end }))") ==
		LUA_OK);
	T_EXPECT_EQ(lua_pcall(L, 0, 0, 1), LUA_ERRRUN);
	const char *restrict const s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	static const char want[] = "(unprintable table: ";
	T_EXPECT(strncmp(s, want, sizeof(want) - 1) == 0);
	T_EXPECT(strstr(s, "stack traceback:") != NULL);
	T_EXPECT(strstr(s, "error in error handling") == NULL);
}

/* Evaluate @p expr for one error object and check how aux_errmsg renders it.
 * The rendering is the sole diagnostic on the ruleset error paths, so every
 * shape ruleset Lua can raise -- including the ones whose __tostring itself
 * fails -- must come back as a usable message and leave the stack no deeper
 * than the one pushed result. */
T_DECLARE_SUBCASE(
	check_errmsg, lua_State *restrict L, const char *restrict expr,
	const char *restrict prefix)
{
	const int base = lua_gettop(L);

	T_CHECK(luaL_loadstring(L, expr) == LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	const char *restrict s = aux_errmsg(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strncmp(s, prefix, strlen(prefix)) == 0);
	T_EXPECT(lua_gettop(L) <= base + 2);
	lua_settop(L, base);
}

T_DECLARE_CASE(base_aux_errmsg_renders_every_error_object)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	/* a string message passes through untouched */
	T_CALL_SUBCASE(
		check_errmsg, L, "return 'ruleset:1: boom'", "ruleset:1: boom");
	/* other primitives render as tostring() would */
	T_CALL_SUBCASE(check_errmsg, L, "return 42", "42");
	T_CALL_SUBCASE(check_errmsg, L, "return nil", "nil");
	/* an object without __tostring: type and address */
	T_CALL_SUBCASE(check_errmsg, L, "return {}", "table: ");
	/* a working __tostring is honored */
	T_CALL_SUBCASE(
		check_errmsg, L,
		"return setmetatable({}, { __tostring = function() return 'denied' end })",
		"denied");
	/* a __tostring that raises must not take the message down with it */
	T_CALL_SUBCASE(
		check_errmsg, L,
		"return setmetatable({}, { __tostring = function() error('nested') end })",
		"(unprintable table: ");
	/* nor one that returns a non-string, which luaL_tolstring rejects */
	T_CALL_SUBCASE(
		check_errmsg, L,
		"return setmetatable({}, { __tostring = function() return {} end })",
		"(unprintable table: ");
	/* the same holds for a non-table carrier */
	T_CALL_SUBCASE(
		check_errmsg, L,
		"local co = coroutine.create(function() end) "
		"debug.setmetatable(co, { __tostring = function() error('nested') end }) "
		"return co",
		"(unprintable thread: ");
}

/* aux_errmsg's last resort: with the stack full it cannot even set up the
 * protected call that renders the object. */
T_DECLARE_CASE(base_aux_errmsg_stack_exhausted)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_CHECK(luaL_loadstring(
			L,
			"return setmetatable({}, { __tostring = function() error('nested') end })") ==
		LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	/* Fill the stack until it cannot take another slot. Lua answers its
	 * first refusal by opening the reserve it keeps for error handling, so
	 * keep filling until a refusal repeats. */
	int refusals = 0;
	while (refusals < 2) {
		if (lua_checkstack(L, 1)) {
			lua_pushnil(L);
			refusals = 0;
			continue;
		}
		refusals++;
	}
	T_CHECK(!lua_checkstack(L, 1));

	T_EXPECT_STREQ(aux_errmsg(L, 1), "(unprintable error object)");

	lua_settop(L, 0);
}

/* Fail every allocation, including the emergency-GC retry that follows the
 * first failure. */
static void *
failing_alloc(void *ud, void *ptr, const size_t osize, const size_t nsize)
{
	const bool *restrict const failing = ud;

	(void)osize;
	if (nsize == 0) {
		free(ptr);
		return NULL;
	}
	if (*failing) {
		return NULL;
	}
	return realloc(ptr, nsize);
}

/* Out of memory is the one failure that defeats both renderings: luaL_tolstring
 * cannot build its result and neither can the type/address fallback. */
T_DECLARE_CASE(base_aux_errmsg_out_of_memory)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);
	static bool failing;
	failing = false;
	lua_setallocf(L, failing_alloc, &failing);

	T_CHECK(luaL_loadstring(
			L,
			"return setmetatable({}, { __tostring = function() error('nested') end })") ==
		LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	/* the same object renders through the fallback while memory is
	 * available, so the literal below is the shortage talking */
	static const char want[] = "(unprintable table: ";
	T_EXPECT(strncmp(aux_errmsg(L, 1), want, sizeof(want) - 1) == 0);
	lua_settop(L, 1);
	/* reserve the stack in advance, so the rendering itself is what fails */
	T_CHECK(lua_checkstack(L, 8));

	failing = true;
	const char *restrict s = aux_errmsg(L, 1);
	failing = false;
	T_EXPECT_STREQ(s, "(unprintable error object)");

	lua_settop(L, 0);
}

T_DECLARE_CASE(base_aux_todialreq_builds_request)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L;
	struct dialreq *req;

	r.basereq =
		dialreq_parse("base.example:443", "socks5://127.0.0.1:1080");
	T_CHECK(r.basereq != NULL);
	T_CLEANUP(free_request, r.basereq);
	L = new_ruleset_lua(_t_, &r);

	lua_pushstring(L, "example.com:80");
	lua_pushstring(L, "http://127.0.0.2:8080");
	T_EXPECT(aux_todialreq(L, 2));
	req = lua_touserdata(L, -1);
	T_CHECK(req != NULL);
	T_CLEANUP(free_request, req);
	T_EXPECT_EQ(req->addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(req->addr.port, UINT16_C(80));
	T_EXPECT_EQ(req->num_proxy, (size_t)2);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[1].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[1].addr.type, ATYP_INET);
	T_EXPECT_EQ(req->proxy[1].addr.port, UINT16_C(8080));
}

T_DECLARE_CASE(base_aux_todialreq_nil_returns_null)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);

	lua_pushnil(L);
	T_EXPECT(aux_todialreq(L, 1));
	T_EXPECT_EQ(lua_touserdata(L, -1), NULL);
}

/* Regression: aux_todialreq must honor its documented [-n, ...] stack effect
 * even on the n > 255 early-out, popping its arguments like every other
 * failure path. */
T_DECLARE_CASE(base_aux_todialreq_overflow_pops_stack)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);

	const int base = lua_gettop(L);
	const int n = 256; /* > 255 */
	T_CHECK(lua_checkstack(L, n + 1));
	for (int i = 0; i < n; i++) {
		lua_pushstring(L, "example.com:80");
	}
	T_EXPECT(!aux_todialreq(L, n));
	T_EXPECT_EQ(lua_gettop(L), base); /* the n arguments must be popped */
}

/* Regression: aux_todialreq's string-content rejection branches (over-long
 * address, unparseable proxy URI, unparseable target) must each pop their n
 * arguments and return false, honoring the documented [-n, ...] stack effect
 * like the n > 255 early-out. */
T_DECLARE_CASE(base_aux_todialreq_rejects_bad_strings_pops_stack)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	const int base = lua_gettop(L);

	/* an address longer than the 1024-byte cap is rejected before any
	 * dialreq is built */
	char big[2000];
	memset(big, 'a', sizeof(big));
	lua_pushlstring(L, big, sizeof(big));
	T_EXPECT(!aux_todialreq(L, 1));
	T_EXPECT_EQ(lua_gettop(L), base);

	/* a proxy URI the dialer cannot parse (unknown scheme) is rejected */
	lua_pushstring(L, "example.com:80");
	lua_pushstring(L, "bogus://127.0.0.1:1080");
	T_EXPECT(!aux_todialreq(L, 2));
	T_EXPECT_EQ(lua_gettop(L), base);

	/* a target address the dialer cannot parse (no host:port) is rejected */
	lua_pushstring(L, "no-colon-no-port");
	T_EXPECT(!aux_todialreq(L, 1));
	T_EXPECT_EQ(lua_gettop(L), base);
}

T_DECLARE_SUBCASE(
	expect_nul_dialreq_rejected, const char *restrict target,
	const size_t target_len, const char *restrict proxy,
	const size_t proxy_len)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	r.basereq =
		dialreq_parse("base.example:443", "socks5://127.0.0.1:1080");
	T_CHECK(r.basereq != NULL);
	T_CLEANUP(free_request, r.basereq);
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	lua_pushstring(L, "sentinel");
	lua_pushlstring(L, target, target_len);
	lua_pushlstring(L, proxy, proxy_len);
	const bool accepted = aux_todialreq(L, 2);
	const int top = lua_gettop(L);
	const bool preserved = strcmp(lua_tostring(L, 1), "sentinel") == 0;
	if (accepted) {
		dialreq_free(lua_touserdata(L, -1));
	}

	T_EXPECT(!accepted);
	T_EXPECT_EQ(top, 1);
	T_EXPECT(preserved);
}

T_DECLARE_CASE(base_aux_todialreq_rejects_nul_target)
{
	static const char target[] = "example.com:443\0.attacker";
	static const char proxy[] = "http://127.0.0.1:8080";
	T_CALL_SUBCASE(
		expect_nul_dialreq_rejected, target, sizeof(target) - 1, proxy,
		sizeof(proxy) - 1);
}

T_DECLARE_CASE(base_aux_todialreq_rejects_nul_proxy)
{
	static const char target[] = "example.com:443";
	static const char proxy[] = "http://127.0.0.1:8080\0.attacker";
	T_CALL_SUBCASE(
		expect_nul_dialreq_rejected, target, sizeof(target) - 1, proxy,
		sizeof(proxy) - 1);
}

T_DECLARE_CASE(base_aux_async_reuses_idle_thread)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	lua_State *co1, *co2;

	async_finish_state = (struct async_finish_record){ 0 };
	co1 = aux_getthread(L);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)1);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);
	/* aux_getthread leaves the coroutine at slot 1, so the finish function
	 * pushed here is at slot 2 -- that is the index aux_async copies from. */
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	T_EXPECT_EQ(aux_async(co1, L, 0, 2), LUA_YIELD);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);
	/* the worker's return value is routed to finish as (ok, results...) */
	T_EXPECT(async_finish_state.called);
	T_EXPECT(async_finish_state.ok);
	T_EXPECT_EQ(async_finish_state.nargs, 2);
	T_EXPECT_EQ(async_finish_state.result, (lua_Integer)99);
	lua_settop(L, 0);

	co2 = aux_getthread(L);
	T_EXPECT_EQ(co2, co1);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)1);
	T_EXPECT_EQ(r.vmstats.num_thread_peak, (size_t)1);
}

#if LUA_VERSION_NUM >= 504
T_DECLARE_CASE(base_aux_getthread_replaces_closed_idle_thread)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *const L = new_ruleset_lua(_t_, &r);
	lua_State *const old = aux_getthread(L);
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	const int first = aux_async(old, L, 0, 2);
	lua_settop(L, 1);
	const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
	const int closed = lua_resetthread(old);
	lua_State *const fresh = aux_getthread(L);
	const bool replaced = (fresh != old);
	async_finish_state = (struct async_finish_record){ 0 };
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	const int second = aux_async(fresh, L, 0, 2);
	const bool completed = async_finish_state.called &&
			       async_finish_state.ok &&
			       async_finish_state.result == 99;
	const size_t active = r.vmstats.num_thread_active;
	luaL_unref(L, LUA_REGISTRYINDEX, ref);

	T_EXPECT_EQ(first, LUA_YIELD);
	T_EXPECT_EQ(closed, LUA_OK);
	T_EXPECT(replaced);
	T_EXPECT_EQ(second, LUA_YIELD);
	T_EXPECT(completed);
	T_EXPECT_EQ(active, (size_t)0);
}
#endif /* LUA_VERSION_NUM >= 504 */

/* Regression: aux_async() must grow the target coroutine's stack for the
 * caller-controlled argument count before the lua_xmove(); without the
 * lua_checkstack() a large narg overran a fresh coroutine's initial stack. */
T_DECLARE_CASE(base_aux_async_grows_thread_stack_for_args)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);

	/* large enough that, without the checkstack, the xmove runs off the end
	 * of a fresh coroutine's stack into unmapped memory (a smaller overrun
	 * can land in allocator slack and go unnoticed) */
	enum { NARG = 20000 };
	async_finish_state = (struct async_finish_record){ 0 };
	lua_State *const co = aux_getthread(L);
	/* Leave two extra slots for aux_async's lifecycle registry lookup. */
	T_CHECK(lua_checkstack(L, NARG + 4));
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, async_worker);
	for (int i = 0; i < NARG; i++) {
		lua_pushinteger(L, i);
	}
	T_EXPECT_EQ(aux_async(co, L, NARG, 2), LUA_YIELD);
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);
	T_EXPECT(async_finish_state.called);
	T_EXPECT(async_finish_state.ok);
	T_EXPECT_EQ(async_finish_state.result, (lua_Integer)99);
}

T_DECLARE_CASE(base_aux_getregtable_rejects_non_table)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);

	/* a non-table registry slot must raise ERR_BAD_REGISTRY */
	lua_pushboolean(L, 1);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);

	lua_pushcfunction(L, getregtable_idle_thunk);
	T_EXPECT_EQ(lua_pcall(L, 0, 1, 0), LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "registry is corrupted") != NULL);
}

T_DECLARE_CASE(base_aux_forward_context_roundtrip)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
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
}

T_DECLARE_CASE(base_ruleset_pcall_success_and_error)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
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
}

#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
T_DECLARE_CASE(base_ruleset_pcall_event_samples_wrap)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *const L = new_ruleset_lua(_t_, &r);
	r.L = L;
	const size_t n = ARRAY_SIZE(r.vmstats.event_ns);
	r.vmstats.num_events = n - 1;
	for (size_t i = 0; i < n; i++) {
		r.vmstats.event_ns[i] = -1;
	}

	/* Cross a seconds boundary and retain a duration wider than int32_t. */
	const struct timespec success[] = {
		{ .tv_sec = 11, .tv_nsec = 950000000 },
		{ .tv_sec = 14, .tv_nsec = 123456789 },
	};
	set_event_clock(success);
	const bool ok = ruleset_pcall(&r, pcall_push_result, 0, 1);
	T_CALL_SUBCASE(check_event_clock, (size_t)2);
	T_EXPECT(ok);
	T_EXPECT_EQ(lua_tointeger(L, -1), (lua_Integer)7);
	T_EXPECT_EQ(r.vmstats.num_events, n);
	for (size_t i = 0; i < n; i++) {
		T_EXPECT_EQ(
			r.vmstats.event_ns[i],
			i == n - 1 ? INT64_C(2173456789) : -1);
	}

	/* A failed call is sampled too, overwriting the first slot on wrap. */
	const struct timespec failure[] = {
		{ .tv_sec = 99, .tv_nsec = 990000000 },
		{ .tv_sec = 100, .tv_nsec = 17 },
	};
	set_event_clock(failure);
	const bool failed = ruleset_pcall(&r, pcall_raise_error, 0, 0);
	T_CALL_SUBCASE(check_event_clock, (size_t)2);
	T_EXPECT(!failed);
	T_EXPECT_EQ(r.vmstats.num_events, n + 1);
	for (size_t i = 0; i < n; i++) {
		int_least64_t expected = -1;
		if (i == 0) {
			expected = INT64_C(10000017);
		} else if (i == n - 1) {
			expected = INT64_C(2173456789);
		}
		T_EXPECT_EQ(r.vmstats.event_ns[i], expected);
	}
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	T_EXPECT_STREQ(lua_tostring(L, -1), "boom");
}
#endif /* HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC) */

T_DECLARE_CASE(base_ruleset_resume_wakes_coroutine)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	r.L = L;

	/* create a coroutine that yields and pin it in the await context */
	lua_State *const co = lua_newthread(L);
	int ctx_key = 0;
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_pushvalue(L, -2); /* co */
	lua_rawsetp(L, -2, &ctx_key);
	lua_pop(L, 1); /* pop the await-context table; co ref remains */

	lua_pushcfunction(co, resume_yield);
	/* aux_resume wraps the 3-arg (Lua 5.3) vs 4-arg (5.4+) lua_resume split */
	T_CHECK(aux_resume(co, L, 0) == LUA_YIELD);
	lua_pop(L,
		1); /* drop the co reference (still kept alive by the table) */

	/* ruleset_resume looks co up by ctx and drives it to completion */
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	const struct timespec readings[] = {
		{ .tv_sec = 3, .tv_nsec = 700000000 },
		{ .tv_sec = 3, .tv_nsec = 700000123 },
	};
	set_event_clock(readings);
#endif
	ruleset_resume(&r, &ctx_key, 0);
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	T_CALL_SUBCASE(check_event_clock, (size_t)2);
	T_EXPECT_EQ(r.vmstats.event_ns[0], INT64_C(123));
	for (size_t i = 1; i < ARRAY_SIZE(r.vmstats.event_ns); i++) {
		T_EXPECT_EQ(r.vmstats.event_ns[i], INT64_C(0));
	}
#endif
	T_EXPECT_EQ(r.vmstats.num_events, (size_t)1);
	lua_getglobal(L, "resumed");
	T_EXPECT(lua_toboolean(L, -1) != 0);
	lua_pop(L, 1);
}

/*
 * A catastrophic lua_resume failure (here forced by corrupting
 * RIDX_IDLE_THREAD so thread_call_k's re-caching raises after the finish
 * callback runs) must decrement num_thread_active exactly once and clear the
 * abandoned coroutine's forward-context entry.
 */
T_DECLARE_CASE(base_aux_async_catastrophic_failure_cleanup)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);

	async_finish_state = (struct async_finish_record){ 0 };
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
	const int status = aux_async(co, L, 0, 2);
	T_EXPECT(status != LUA_OK && status != LUA_YIELD);
	/* the raise happens in the re-caching after the finish dispatch */
	T_EXPECT(async_finish_state.called);

	/* decremented exactly once (0), not double-counted (SIZE_MAX) */
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)0);

	lua_settop(L, 0);
	/* the abandoned coroutine's forward-context entry is cleared */
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
	lua_rawgetp(L, -1, co);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);
}

/* A stream that yields a chunk on its first direct_read and then either EOF or
 * a read error, to exercise aux_load()'s mid-stream error handling. */
struct fault_stream {
	struct io_stream stream;
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

static const struct io_stream_vftable fault_stream_vftable = {
	.direct_read = fault_stream_direct_read,
};

/* Regression: aux_load() must report a mid-stream read error as a load
 * failure, not let lua_load() treat the truncated input as a clean EOF and
 * compile the (valid-prefix) partial chunk. */
T_DECLARE_CASE(base_aux_load_reports_mid_stream_read_error)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/* ruleset_resume with a corrupted RIDX_AWAIT_CONTEXT (not a table) stores
 * ERR_BAD_REGISTRY into RIDX_LASTERROR and returns without touching the thread
 * bookkeeping. */
T_DECLARE_CASE(base_ruleset_resume_bad_await_context)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	r.L = L;

	/* corrupt the await-context slot to a non-table */
	lua_pushboolean(L, 1);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);

	int ctx_key = 0;
	r.vmstats.num_thread_active = 3;
	ruleset_resume(&r, &ctx_key, 0);

	/* the early error path does not decrement the active count */
	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)3);
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	T_EXPECT(lua_isstring(L, -1));
	T_EXPECT(strstr(lua_tostring(L, -1), "registry is corrupted") != NULL);
	lua_pop(L, 1);
}

/* ruleset_resume for a ctx with no await-context entry (co == NULL) returns
 * early ("async context lost") without decrementing the active count. */
T_DECLARE_CASE(base_ruleset_resume_context_lost)
{
	static struct config conf;
	conf = (struct config){ 0 };
	static struct ruleset r;
	r = (struct ruleset){ .conf = &conf };
	lua_State *restrict L = new_ruleset_lua(_t_, &r);
	r.L = L;

	int ctx_key = 0; /* never registered in the await context */
	r.vmstats.num_thread_active = 3;
	ruleset_resume(&r, &ctx_key, 0);

	T_EXPECT_EQ(r.vmstats.num_thread_active, (size_t)3);
}

struct resume_fixture {
	struct config conf;
	struct ruleset ruleset;
};

static void cleanup_resume_fixture(void *data)
{
	struct resume_fixture *f = data;
	free(f);
}

T_DECLARE_CASE(base_ruleset_resume_unpooled_failure)
{
	struct resume_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	struct ruleset *r = &f->ruleset;
	r->conf = &f->conf;
	T_CLEANUP(cleanup_resume_fixture, f);
	lua_State *restrict L = new_ruleset_lua(_t_, r);
	r->L = L;
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);

	lua_State *const co = lua_newthread(L);
	int ctx_key = 0;
	/* pin co in the await context under ctx_key */
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_pushvalue(L, -2); /* co */
	lua_rawsetp(L, -2, &ctx_key);
	lua_pop(L, 1);
	/* and register a forward-context entry for co */
	int fwd_state = 0;
	aux_setforward(L, co, &fwd_state);

	/* start the coroutine so it yields with an error-raising continuation */
	lua_pushcfunction(co, resume_yield_then_error);
	T_CHECK(aux_resume(co, L, 0) == LUA_YIELD);
	lua_pop(L, 1); /* drop co ref (kept alive by the tables) */

	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	const struct timespec readings[] = {
		{ .tv_sec = 7, .tv_nsec = 999999999 },
		{ .tv_sec = 8, .tv_nsec = 1 },
	};
	set_event_clock(readings);
#endif
	ruleset_resume(r, &ctx_key, 0);
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	T_CALL_SUBCASE(check_event_clock, (size_t)2);
	T_EXPECT_EQ(r->vmstats.event_ns[0], INT64_C(2));
	for (size_t i = 1; i < ARRAY_SIZE(r->vmstats.event_ns); i++) {
		T_EXPECT_EQ(r->vmstats.event_ns[i], INT64_C(0));
	}
#endif
	T_EXPECT_EQ(r->vmstats.num_events, (size_t)1);

	/* A raw coroutine never acquired an active pool slot. */
	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);

	lua_settop(L, 0);
	/* forward-context entry for co cleared */
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
	lua_rawgetp(L, -1, co);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);
	/* await-context entry for ctx cleared */
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_rawgetp(L, -1, &ctx_key);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);
	/* the error was stored in the coroutine's RIDX_LASTERROR */
	lua_rawgeti(co, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	T_EXPECT(!lua_isnil(co, -1));
}

T_DECLARE_CASE(base_ruleset_resume_catastrophic_failure)
{
	struct resume_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	struct ruleset *r = &f->ruleset;
	r->conf = &f->conf;
	T_CLEANUP(cleanup_resume_fixture, f);
	lua_State *restrict L = new_ruleset_lua(_t_, r);
	r->L = L;
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);

	lua_State *const co = aux_getthread(L);
	T_EXPECT_EQ(r->vmstats.num_thread_active, 1);
	int ctx_key = 0;
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_pushvalue(L, -2);
	lua_rawsetp(L, -2, &ctx_key);
	lua_pop(L, 1);
	int fwd_state = 0;
	aux_setforward(L, co, &fwd_state);

	async_finish_state = (struct async_finish_record){ 0 };
	lua_pushcfunction(L, async_finish);
	lua_pushcfunction(L, resume_yield);
	T_EXPECT_EQ(aux_async(co, L, 0, 2), LUA_YIELD);
	T_EXPECT_EQ(r->vmstats.num_thread_active, 1);
	lua_settop(L, 0);

	/* The worker returns normally, then the pool cache raises before release. */
	lua_pushboolean(L, 1);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	ruleset_resume(r, &ctx_key, 0);
	T_EXPECT(async_finish_state.called);
	T_EXPECT(async_finish_state.ok);
	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);

	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
	lua_rawgetp(L, -1, co);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_rawgetp(L, -1, &ctx_key);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 2);
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	T_EXPECT_STREQ(lua_tostring(L, -1), ERR_BAD_REGISTRY);
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static struct ruleset failure_ruleset;
static struct config failure_conf;

T_DECLARE_CASE(base_fixture_intentional_failure)
{
	failure_ruleset = (struct ruleset){ .conf = &failure_conf };
	lua_State *L = new_ruleset_lua(_t_, &failure_ruleset);
	(void)aux_getthread(L);
	T_CHECK(failure_ruleset.vmstats.num_thread_active == 1);
	T_EXPECT(false);
}

T_DECLARE_CASE(base_failed_expectation_closes_lua)
{
	const unsigned before = lua_close_count;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, base_fixture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(lua_close_count, before + 1);
	T_EXPECT_EQ(failure_ruleset.vmstats.num_thread_active, (size_t)0);
}

static const struct testing_suite suite[] = {
	T_CASE(base_failed_expectation_closes_lua),
	T_CASE(base_aux_newweaktable_v),
	T_CASE(base_aux_newweaktable_k),
	T_CASE(base_aux_toclose_sets_gc),
	T_CASE(base_aux_close_behavior),
	T_CASE(base_thread_bootstrap_oom_is_protected),
	T_CASE(base_thread_repairs_incomplete_metatable),
	T_CASE(base_guard_oom_retry_finalizes_abandoned_coroutine),
	T_CASE(base_aux_format_addr_ipv4),
	T_CASE(base_aux_format_addr_ipv6),
	T_CASE(base_aux_format_addr_null),
	T_CASE(base_aux_format_addr_unknown_family),
	T_CASE(base_aux_traceback_renders_error_object),
	T_CASE(base_aux_traceback_survives_raising_tostring),
	T_CASE(base_aux_errmsg_renders_every_error_object),
	T_CASE(base_aux_errmsg_stack_exhausted),
	T_CASE(base_aux_errmsg_out_of_memory),
	T_CASE(base_aux_todialreq_builds_request),
	T_CASE(base_aux_todialreq_nil_returns_null),
	T_CASE(base_aux_todialreq_overflow_pops_stack),
	T_CASE(base_aux_todialreq_rejects_bad_strings_pops_stack),
	T_CASE(base_aux_todialreq_rejects_nul_target),
	T_CASE(base_aux_todialreq_rejects_nul_proxy),
	T_CASE(base_aux_async_reuses_idle_thread),
#if LUA_VERSION_NUM >= 504
	T_CASE(base_aux_getthread_replaces_closed_idle_thread),
#endif
	T_CASE(base_aux_async_grows_thread_stack_for_args),
	T_CASE(base_aux_getregtable_rejects_non_table),
	T_CASE(base_aux_forward_context_roundtrip),
	T_CASE(base_ruleset_pcall_success_and_error),
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	T_CASE(base_ruleset_pcall_event_samples_wrap),
#endif
	T_CASE(base_ruleset_resume_wakes_coroutine),
	T_CASE(base_aux_async_catastrophic_failure_cleanup),
	T_CASE(base_aux_load_reports_mid_stream_read_error),
	T_CASE(base_ruleset_resume_bad_await_context),
	T_CASE(base_ruleset_resume_context_lost),
	T_CASE(base_ruleset_resume_unpooled_failure),
	T_CASE(base_ruleset_resume_catastrophic_failure),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
