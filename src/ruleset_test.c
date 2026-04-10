/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utils/testing.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdlib.h>

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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_lua_state_creation);
	T_RUN_CASE(t, test_lua_table_operations);
	T_RUN_CASE(t, test_lua_string_manipulation);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
