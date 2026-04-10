/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <stdbool.h>
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

T_DECLARE_CASE(test_cfunc_lua_table_creation)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	lua_createtable(L, 0, 4);
	lua_pushinteger(L, 100);
	lua_setfield(L, -2, "count");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "count");
	T_EXPECT_EQ(lua_tointeger(L, -1), 100);
	lua_close(L);
}

T_DECLARE_CASE(test_cfunc_lua_function_call)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	lua_getglobal(L, "table");
	T_EXPECT(lua_istable(L, -1));
	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, test_cfunc_lua_table_creation);
	T_RUN_CASE(t, test_cfunc_lua_function_call);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
