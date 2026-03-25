/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/base.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <arpa/inet.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int g_close_called;

static int test_close(lua_State *restrict L)
{
	(void)L;
	g_close_called++;
	return 0;
}

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	return L;
}

T_DECLARE_CASE(base_aux_newweaktable_v)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	aux_newweaktable(L, "v");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "v");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_newweaktable_k)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	aux_newweaktable(L, "k");
	T_EXPECT(lua_istable(L, -1));
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__mode");
	T_EXPECT_STREQ(lua_tostring(L, -1), "k");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_toclose_sets_gc)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	g_close_called = 0;
	(void)lua_newuserdata(L, sizeof(uint_least8_t));
	aux_toclose(L, -1, "test.close.mt", test_close);
	T_EXPECT(lua_getmetatable(L, -1) != 0);
	lua_getfield(L, -1, "__gc");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(base_aux_close_behavior)
{
	lua_State *restrict L = new_lua();
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

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_ipv4)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	T_CHECK(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "127.0.0.1");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_ipv6)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	T_CHECK(inet_pton(AF_INET6, "::1", &sa.sin6_addr) == 1);
	lua_pushlightuserdata(L, &sa);
	T_EXPECT_EQ(aux_format_addr(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "::1");

	lua_close(L);
}

T_DECLARE_CASE(base_aux_format_addr_null)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_pushlightuserdata(L, NULL);
	T_EXPECT_EQ(aux_format_addr(L), 0);

	lua_close(L);
}

T_DECLARE_CASE(base_aux_traceback_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_pushliteral(L, "boom");
	T_EXPECT_EQ(aux_traceback(L), 1);
	const char *restrict s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strstr(s, "boom") != NULL);

	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, base_aux_newweaktable_v);
	T_RUN_CASE(t, base_aux_newweaktable_k);
	T_RUN_CASE(t, base_aux_toclose_sets_gc);
	T_RUN_CASE(t, base_aux_close_behavior);
	T_RUN_CASE(t, base_aux_format_addr_ipv4);
	T_RUN_CASE(t, base_aux_format_addr_ipv6);
	T_RUN_CASE(t, base_aux_format_addr_null);
	T_RUN_CASE(t, base_aux_traceback_string);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
