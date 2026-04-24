/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utils/testing.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdlib.h>
#include <string.h>

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	return L;
}

T_DECLARE_CASE(test_lua_state_creation)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	T_EXPECT(lua_gettop(L) == 0);
	lua_close(L);
}

T_DECLARE_CASE(test_lua_table_operations)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	lua_newtable(L);
	T_EXPECT(lua_istable(L, -1));
	lua_setfield(L, LUA_REGISTRYINDEX, "test_table");
	lua_getfield(L, LUA_REGISTRYINDEX, "test_table");
	T_EXPECT(lua_istable(L, -1));
	lua_close(L);
}

T_DECLARE_CASE(test_lua_string_manipulation)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	lua_pushstring(L, "test");
	const char *str = lua_tostring(L, -1);
	T_EXPECT_STREQ(str, "test");
	lua_close(L);
}

/*
 * lua_pcall is the cornerstone of ruleset_pcall: verify it catches runtime
 * errors and returns an error message rather than aborting the process.
 */
T_DECLARE_CASE(test_lua_pcall_catches_runtime_error)
{
	lua_State *restrict L = new_lua();
	int rc;

	T_CHECK(L != NULL);

	/* Compile and call a chunk that raises a runtime error. */
	rc = luaL_loadstring(L, "error('sentinel')");
	T_EXPECT_EQ(rc, LUA_OK);
	rc = lua_pcall(L, 0, 0, 0);
	T_EXPECT_EQ(rc, LUA_ERRRUN);
	T_EXPECT(lua_isstring(L, -1));

	/* The error message must contain the literal we raised. */
	const char *msg = lua_tostring(L, -1);
	T_EXPECT(msg != NULL);
	T_EXPECT(strstr(msg, "sentinel") != NULL);

	lua_close(L);
}

/*
 * Coroutines underlie the await/async mechanism.  Confirm that yield and
 * resume transfer control correctly between the host and a coroutine.
 */
T_DECLARE_CASE(test_lua_coroutine_yield_and_resume)
{
	lua_State *restrict L = new_lua();
	lua_State *co;
	int nres;
	int rc;

	T_CHECK(L != NULL);

	/* Create a coroutine and load the chunk directly onto its stack. */
	co = lua_newthread(L); /* L's stack: [co_thread] */
	rc = luaL_loadstring(
		co, "local x = coroutine.yield(1)\n"
		    "return x + 10");
	T_EXPECT_EQ(rc, LUA_OK);

	/* First resume: runs until the yield, returns 1 value. */
	rc = lua_resume(co, L, 0, &nres);
	T_EXPECT_EQ(rc, LUA_YIELD);
	T_EXPECT_EQ(nres, 1);
	T_EXPECT_EQ(lua_tointeger(co, -1), 1);
	lua_pop(co, nres);

	/* Second resume: pass 5 back, coroutine returns 5+10=15. */
	lua_pushinteger(co, 5);
	rc = lua_resume(co, L, 1, &nres);
	T_EXPECT_EQ(rc, LUA_OK);
	T_EXPECT_EQ(nres, 1);
	T_EXPECT_EQ(lua_tointeger(co, -1), 15);
	lua_pop(co, nres);

	lua_pop(L, 1); /* release co_thread reference */
	lua_close(L);
}

/*
 * The registry (LUA_REGISTRYINDEX) is used by the ruleset to store per-VM
 * state (RIDX_LASTERROR, RIDX_AWAIT_CONTEXT, etc.).  Verify round-trip
 * storage and retrieval preserves value and type.
 */
T_DECLARE_CASE(test_lua_registry_integer_roundtrip)
{
	lua_State *restrict L = new_lua();
	const lua_Integer key = 42;
	const lua_Integer value = 12345;

	T_CHECK(L != NULL);

	lua_pushinteger(L, value);
	lua_rawseti(L, LUA_REGISTRYINDEX, key);

	const int tp = lua_rawgeti(L, LUA_REGISTRYINDEX, key);
	T_EXPECT_EQ(tp, LUA_TNUMBER);
	T_EXPECT_EQ(lua_tointeger(L, -1), value);

	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_lua_state_creation);
	T_RUN_CASE(t, test_lua_table_operations);
	T_RUN_CASE(t, test_lua_string_manipulation);
	T_RUN_CASE(t, test_lua_pcall_catches_runtime_error);
	T_RUN_CASE(t, test_lua_coroutine_yield_and_resume);
	T_RUN_CASE(t, test_lua_registry_integer_roundtrip);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
