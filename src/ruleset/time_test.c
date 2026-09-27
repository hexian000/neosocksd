/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * time_test - white-box unit tests for ruleset/time.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/time.c   module under test
 * Leaf libraries: Lua. time.c's only collaborator is os/clock.h, whose readings
 * are static inlines over clock_gettime(); the mock section replaces that call.
 */

#include "time.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures and a clock_gettime() test stub.
 * ---------------------------------------------------------------------- */

#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
/* clock_gettime() test stub. clock_monotonic() is
 * a static inline over it, so this is the only point a clock failure reaches
 * time.c. Only CLOCK_MONOTONIC is ever failed, and only while armed, leaving
 * the time.unix()/process()/thread() cases on the real clock. */
static unsigned g_monotonic_calls;
static unsigned g_fail_monotonic_call; /* 0 = disabled */

int test_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	if (clk_id == CLOCK_MONOTONIC) {
		g_monotonic_calls++;
		if (g_monotonic_calls == g_fail_monotonic_call) {
			errno = EINVAL;
			return -1;
		}
	}
	return clock_gettime(clk_id, tp);
}

/* Fail the n-th monotonic reading taken from now on, 0 to disarm.
 * time.measure() takes two, one before the measured call and one after. */
static void fail_monotonic_at(const unsigned n)
{
	g_monotonic_calls = 0;
	g_fail_monotonic_call = n;
}
#endif /* HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC) */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_time(L);
	lua_setglobal(L, "time");
	return L;
}

static bool run_chunk(lua_State *restrict L, const char *restrict chunk)
{
	const int status_load = luaL_loadstring(L, chunk);
	if (status_load != LUA_OK) {
		return false;
	}
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	return status_call == LUA_OK;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - time formatting/parsing cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(time_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "time");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "monotonic");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "process");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -3, "thread");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -4, "unix");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -5, "measure");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(time_monotonic_positive)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return time.monotonic()"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_tonumber(L, 1) > 0.0);

	lua_close(L);
}

T_DECLARE_CASE(time_unix_sanity)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return time.unix()"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_tonumber(L, 1) > 1000000000.0);

	lua_close(L);
}

T_DECLARE_CASE(time_process_and_thread)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return time.process(), time.thread()"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_tonumber(L, 1) >= 0.0);
	T_EXPECT(lua_isnumber(L, 2));
	T_EXPECT(lua_tonumber(L, 2) >= -1.0);

	lua_close(L);
}

T_DECLARE_CASE(time_measure_basic)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return time.measure(function() return 42 end)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_tonumber(L, 1) >= -1.0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 42);

	lua_close(L);
}

T_DECLARE_CASE(time_measure_passes_results)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"return time.measure(function(a, b) return a + b, a * b end, 6, 7)"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_tonumber(L, 1) >= -1.0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 13);
	T_EXPECT_EQ(lua_tointeger(L, 3), 42);

	lua_close(L);
}

T_DECLARE_CASE(time_measure_rejects_missing_function)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* no function argument: must raise rather than call a bogus slot */
	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(time.measure) "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *const err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "function expected") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(time_measure_propagates_error)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* an error raised inside the measured function must surface unchanged,
	 * not be swallowed into a -1 cost */
	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(time.measure, "
		   "function() error(\"boom\") end) "
		   "return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *const err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "boom") != NULL);

	lua_close(L);
}

#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
/*
 * Either monotonic reading failing makes time.measure() hand back its cost
 * placeholder unreplaced. That placeholder must carry the same float subtype
 * the success path returns, which math.type() and marshal() both discriminate.
 */
T_DECLARE_CASE(time_measure_start_clock_failure_cost_is_float)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	fail_monotonic_at(1);
	const bool ok =
		run_chunk(L, "return time.measure(function() return 42 end)");
	const unsigned nreadings = g_monotonic_calls;
	fail_monotonic_at(0);
	T_EXPECT(ok);
	T_EXPECT_EQ(nreadings, 2u);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_isinteger(L, 1) == 0);
	T_EXPECT(lua_tonumber(L, 1) == -1.0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 42);

	lua_close(L);
}

T_DECLARE_CASE(time_measure_end_clock_failure_cost_is_float)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	fail_monotonic_at(2);
	const bool ok =
		run_chunk(L, "return time.measure(function() return 42 end)");
	const unsigned nreadings = g_monotonic_calls;
	fail_monotonic_at(0);
	T_EXPECT(ok);
	T_EXPECT_EQ(nreadings, 2u);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_isinteger(L, 1) == 0);
	T_EXPECT(lua_tonumber(L, 1) == -1.0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 42);

	lua_close(L);
}

/*
 * push_clock() (behind time.monotonic/process/thread/unix) hands back its
 * clock-failure placeholder as a float, the same subtype the success path
 * returns and the subtype math.type()/marshal() discriminate. Only
 * CLOCK_MONOTONIC can be failed here, so time.monotonic() stands in for the
 * shared helper.
 */
T_DECLARE_CASE(time_monotonic_clock_failure_is_float)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	fail_monotonic_at(1);
	const bool ok = run_chunk(L, "return time.monotonic()");
	const unsigned nreadings = g_monotonic_calls;
	fail_monotonic_at(0);
	T_EXPECT(ok);
	T_EXPECT_EQ(nreadings, 1u);
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_isnumber(L, 1));
	T_EXPECT(lua_isinteger(L, 1) == 0);
	T_EXPECT(lua_tonumber(L, 1) == -1.0);

	lua_close(L);
}
#endif /* HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC) */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(time_module_opens),
	T_CASE(time_monotonic_positive),
	T_CASE(time_unix_sanity),
	T_CASE(time_process_and_thread),
	T_CASE(time_measure_basic),
	T_CASE(time_measure_passes_results),
	T_CASE(time_measure_rejects_missing_function),
	T_CASE(time_measure_propagates_error),
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	T_CASE(time_measure_start_clock_failure_cost_is_float),
	T_CASE(time_measure_end_clock_failure_cost_is_float),
	T_CASE(time_monotonic_clock_failure_is_float),
#endif /* HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC) */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
