/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * regex_test - white-box unit tests for ruleset/regex.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/regex.c  module under test
 * Leaf libraries: Lua. regex.c has no stateful collaborator to mock; the mock
 * section only holds shared Lua test fixtures.
 */

#include "ruleset/regex.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <stdbool.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (regex.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_regex(L);
	lua_setglobal(L, "regex");
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
 * regression - pattern compile/match cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(regex_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "regex");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "compile");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "find");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -3, "match");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -4, "gmatch");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(regex_compile_basic)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('hello') return type(r)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "userdata");

	lua_close(L);
}

T_DECLARE_CASE(regex_compile_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	const int status_load = luaL_loadstring(
		L,
		"local ok, err = pcall(regex.compile, '[') return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(regex_find_match)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "return regex.find(r, 'xxabbbz')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_EQ(lua_tointeger(L, 2), 6);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_nomatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('ab+') return regex.find(r, 'xyz')"));
	T_EXPECT_EQ(lua_gettop(L), 0);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_with_init)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "local s1, e1 = regex.find(r, 'ab abbb', 1) "
		   "local s2, e2 = regex.find(r, 'ab abbb', 4) "
		   "local s3, e3 = regex.find(r, 'xxabyyabz', -3) "
		   "return s1, e1, s2, e2, s3, e3"));
	T_EXPECT_EQ(lua_gettop(L), 6);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1);
	T_EXPECT_EQ(lua_tointeger(L, 2), 2);
	T_EXPECT_EQ(lua_tointeger(L, 3), 4);
	T_EXPECT_EQ(lua_tointeger(L, 4), 7);
	T_EXPECT_EQ(lua_tointeger(L, 5), 7);
	T_EXPECT_EQ(lua_tointeger(L, 6), 8);

	lua_close(L);
}

T_DECLARE_CASE(regex_match_captures)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('(foo)(bar)') "
		   "return regex.match(r, 'xxfoobarzz')"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "foobar");
	T_EXPECT_STREQ(lua_tostring(L, 2), "foo");
	T_EXPECT_STREQ(lua_tostring(L, 3), "bar");

	lua_close(L);
}

T_DECLARE_CASE(regex_match_nomatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('foo') return regex.match(r, 'bar')"));
	T_EXPECT_EQ(lua_gettop(L), 0);

	lua_close(L);
}

T_DECLARE_CASE(regex_gmatch_iterator)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('[0-9]+') "
		   "local it = regex.gmatch(r, '1 22 333') "
		   "local a, b, c, d = it(), it(), it(), it() "
		   "return a, b, c, d"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_STREQ(lua_tostring(L, 1), "1");
	T_EXPECT_STREQ(lua_tostring(L, 2), "22");
	T_EXPECT_STREQ(lua_tostring(L, 3), "333");
	T_EXPECT(lua_isnil(L, 4));

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(regex_module_opens),    T_CASE(regex_compile_basic),
	T_CASE(regex_compile_invalid), T_CASE(regex_find_match),
	T_CASE(regex_find_nomatch),    T_CASE(regex_find_with_init),
	T_CASE(regex_match_captures),  T_CASE(regex_match_nomatch),
	T_CASE(regex_gmatch_iterator), T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
