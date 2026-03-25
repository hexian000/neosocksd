/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/marshal.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <stdbool.h>
#include <stdlib.h>

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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, marshal_module_opens);
	T_RUN_CASE(t, marshal_nil_and_bool);
	T_RUN_CASE(t, marshal_integer_and_roundtrip);
	T_RUN_CASE(t, marshal_number_specials);
	T_RUN_CASE(t, marshal_string_roundtrip);
	T_RUN_CASE(t, marshal_table_roundtrip);
	T_RUN_CASE(t, marshal_unsupported_type);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
