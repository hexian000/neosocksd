/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/zlib.h"

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
	(void)luaopen_zlib(L);
	lua_setglobal(L, "zlib");
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

T_DECLARE_CASE(zlib_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "compress");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "uncompress");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(zlib_roundtrip_small)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello zlib hello zlib' "
		   "local z = zlib.compress(s) "
		   "local u = zlib.uncompress(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_roundtrip_large)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('abc123'):rep(20000) "
		   "local z = zlib.compress(s) "
		   "local u = zlib.uncompress(z) "
		   "return #s, #z, #u, s == u"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), 120000);
	T_EXPECT(lua_tointeger(L, 2) > 0);
	T_EXPECT_EQ(lua_tointeger(L, 3), 120000);
	T_EXPECT(lua_toboolean(L, 4) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_empty_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.compress('') "
		   "local u = zlib.uncompress(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_uncompress_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.uncompress, 'not-zlib-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(gzip_module_has_funcs)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "gzip");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "gunzip");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(gzip_roundtrip_small)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello gzip hello gzip' "
		   "local z = zlib.gzip(s) "
		   "local u = zlib.gunzip(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gzip_roundtrip_large)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('abc123'):rep(20000) "
		   "local z = zlib.gzip(s) "
		   "local u = zlib.gunzip(z) "
		   "return #s, #z, #u, s == u"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), 120000);
	T_EXPECT(lua_tointeger(L, 2) > 0);
	T_EXPECT_EQ(lua_tointeger(L, 3), 120000);
	T_EXPECT(lua_toboolean(L, 4) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gzip_empty_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('') "
		   "local u = zlib.gunzip(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gunzip_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.gunzip, 'not-gzip-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(gunzip_crc_mismatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('hello') "
		   "local bad = z:sub(1, #z - 8) .. string.rep('\\0', 8) "
		   "local ok, err = pcall(zlib.gunzip, bad) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, zlib_module_opens);
	T_RUN_CASE(t, zlib_roundtrip_small);
	T_RUN_CASE(t, zlib_roundtrip_large);
	T_RUN_CASE(t, zlib_empty_string);
	T_RUN_CASE(t, zlib_uncompress_invalid);
	T_RUN_CASE(t, gzip_module_has_funcs);
	T_RUN_CASE(t, gzip_roundtrip_small);
	T_RUN_CASE(t, gzip_roundtrip_large);
	T_RUN_CASE(t, gzip_empty_string);
	T_RUN_CASE(t, gunzip_invalid);
	T_RUN_CASE(t, gunzip_crc_mismatch);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
