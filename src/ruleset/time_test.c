/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * time_test - white-box unit tests for ruleset/time.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/time.c   module under test
 * Leaf libraries: Lua. time.c has no stateful collaborator to mock; the mock
 * section only holds shared Lua test fixtures.
 */

#include "ruleset/time.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <stdbool.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (time.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

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
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
