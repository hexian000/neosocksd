/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * marshal_test - white-box unit tests for ruleset/marshal.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/marshal.c  module under test
 *   ruleset/base.c     ruleset Lua substrate
 *   util.c             leaf
 *   dialer.c, resolver.c  linked for symbols bound by the Lua base library
 *   version.c          leaf
 * No stateful collaborator to mock; the mock section holds Lua fixtures.
 */

#include "ruleset/marshal.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (marshal.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_marshal(L);
	lua_setglobal(L, "marshal");
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
 * regression - value (de)serialization round-trip cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(marshal_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "marshal");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(marshal_nil_and_bool)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "return marshal(nil), marshal(true), marshal(false)"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "nil");
	T_EXPECT_STREQ(lua_tostring(L, 2), "true");
	T_EXPECT_STREQ(lua_tostring(L, 3), "false");

	lua_close(L);
}

T_DECLARE_CASE(marshal_integer_and_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s1 = marshal(0) "
		   "local s2 = marshal(42) "
		   "local s3 = marshal(-1) "
		   "local f1 = assert(load('return '..s1)) "
		   "local f2 = assert(load('return '..s2)) "
		   "local f3 = assert(load('return '..s3)) "
		   "return f1(), f2(), f3()"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 42);
	T_EXPECT_EQ(lua_tointeger(L, 3), -1);

	lua_close(L);
}

T_DECLARE_CASE(marshal_number_specials)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local mnan = marshal(0/0) "
		   "local minf = marshal(1/0) "
		   "local mninf = marshal(-1/0) "
		   "return mnan, minf, mninf"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "0/0");
	T_EXPECT_STREQ(lua_tostring(L, 2), "1/0");
	T_EXPECT_STREQ(lua_tostring(L, 3), "-1/0");

	lua_close(L);
}

T_DECLARE_CASE(marshal_float_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* Float zero serializes to "0"; finite floats use hex-float notation.
	 * Each must round-trip exactly through load(). The 0.0 case also forces
	 * a float (1/2 + ... ) so it is not reduced to an integer. */
	T_EXPECT(run_chunk(
		L, "local vals = {0.0, 1.5, -2.25, 0.1, 1e300, 4.0} "
		   "for _, v in ipairs(vals) do "
		   "  local m = marshal(v) "
		   "  local f = assert(load('return '..m)) "
		   "  if f() ~= v then return false, v, m end "
		   "end "
		   "return true"));
	T_EXPECT(lua_gettop(L) >= 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_large_integer_hex)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* Integers above 999999999999 are serialized as hex for compactness;
	 * they must still round-trip through load(). */
	T_EXPECT(run_chunk(
		L, "local vals = {1000000000000, 0x123456789abc, "
		   "-0x7fffffffffffffff, math.maxinteger, math.mininteger} "
		   "for _, v in ipairs(vals) do "
		   "  local m = marshal(v) "
		   "  local f = assert(load('return '..m)) "
		   "  if f() ~= v then return false, v, m end "
		   "end "
		   "return true"));
	T_EXPECT(lua_gettop(L) >= 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_float_zero)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A genuine float zero (not the integer 0) marshals to "0". */
	T_EXPECT(run_chunk(L, "return marshal(0.0)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "0");

	lua_close(L);
}

T_DECLARE_CASE(marshal_string_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'A\\nB\\001\\\\\"' "
		   "local m = marshal(s) "
		   "local f = assert(load('return '..m)) "
		   "return f() == s"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_table_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local t = {1, 'a', true, key = 'val'} "
		"local m = marshal(t) "
		"local f = assert(load('return '..m)) "
		"local r = f() "
		"return r[1] == 1 and r[2] == 'a' and r[3] == true and r.key == 'val'"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_unsupported_type)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(marshal, function() end) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(marshal_circular_table_rejected)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A table referencing itself must raise rather than recurse forever. */
	T_EXPECT(run_chunk(
		L, "local t = {} t.self = t "
		   "local ok, err = pcall(marshal, t) "
		   "return ok, tostring(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT(strstr(lua_tostring(L, 2), "circular") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(marshal_table_with_metatable_warns)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A metatable is not marshalled but the plain table still round-trips;
	 * this also exercises the metatable warning path. */
	T_EXPECT(run_chunk(
		L,
		"local t = setmetatable({1, 2}, {__index = function() end}) "
		"local m = marshal(t) "
		"local r = assert(load('return '..m))() "
		"return r[1] == 1 and r[2] == 2 and getmetatable(r) == nil"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - marshal (encode to Lua source) + decode round-trip of a mixed
 * table, the shape used by RPC/gossip payloads. Runs only when a name filter
 * selects it (e.g. --run bench); a plain ctest run skips it.
 * ---------------------------------------------------------------------- */

T_DECLARE_BENCH(bench_marshal_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	static const char setup[] =
		"local t = {1, 2, 3, 'hello', true, 3.14, "
		"name = 'neosocksd', nested = {a = 1, b = 'x', c = {4, 5, 6}}} "
		"return function() "
		"  return assert(load('return '..marshal(t)))() "
		"end";
	T_CHECK(luaL_loadstring(L, setup) == LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	const int fref = luaL_ref(L, LUA_REGISTRYINDEX);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		lua_rawgeti(L, LUA_REGISTRYINDEX, fref);
		T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
		lua_pop(L, 1);
	}

	luaL_unref(L, LUA_REGISTRYINDEX, fref);
	lua_close(L);
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(marshal_module_opens),
	T_CASE(marshal_nil_and_bool),
	T_CASE(marshal_integer_and_roundtrip),
	T_CASE(marshal_number_specials),
	T_CASE(marshal_float_roundtrip),
	T_CASE(marshal_large_integer_hex),
	T_CASE(marshal_float_zero),
	T_CASE(marshal_string_roundtrip),
	T_CASE(marshal_table_roundtrip),
	T_CASE(marshal_unsupported_type),
	T_CASE(marshal_circular_table_rejected),
	T_CASE(marshal_table_with_metatable_warns),
	T_BENCH(bench_marshal_roundtrip),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
