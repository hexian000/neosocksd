/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/api.h"

#include "ruleset/base.h"

#include "api_client.h"
#include "dialer.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * api.c and base.c are included as sources.  The stubs below satisfy their
 * external dependencies that are outside the scope of these tests.  The
 * tested functions (parse_ipv4, parse_ipv6, splithostport, traceback) do
 * not access a live ruleset, so aux_getruleset returning NULL is fine.
 */

/* ---- dialer stubs (required by base.c's aux_todialreq) ---- */

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	(void)base;
	(void)num_proxy;
	return NULL;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	(void)req;
	(void)proxy_uri;
	(void)urilen;
	return false;
}

void dialreq_free(struct dialreq *req)
{
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	(void)addr;
	(void)s;
	(void)len;
	return false;
}

/* ---- resolver stub (required by api.c's api_stats) ---- */

const struct resolver_stats *resolver_stats(const struct resolver *restrict r)
{
	(void)r;
	return NULL;
}

/* ---- server stub (required by api.c's api_stats) ---- */

void server_stats(
	const struct server *restrict s, struct server_stats *restrict out)
{
	(void)s;
	(void)memset(out, 0, sizeof(*out));
}

/* ---- api_client stub (required by api.c's api_invoke) ---- */

void api_client_invoke(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const void *restrict payload, const size_t len,
	const struct config *restrict conf,
	struct resolver *restrict resolver)
{
	(void)loop;
	(void)req;
	(void)payload;
	(void)len;
	(void)conf;
	(void)resolver;
}

/* ---- util stub (required by util.c's loadlibs if ever called) ---- */

const char *neosocksd_version(void)
{
	return "test";
}

int dialreq_format(
	char *restrict s, const size_t maxlen,
	const struct dialreq *restrict r)
{
	(void)s;
	(void)maxlen;
	(void)r;
	return -1;
}

void resolver_init(void) {}
void resolver_cleanup(void) {}

/* ---- Lua helpers ---- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_neosocksd(L);
	lua_setglobal(L, "neosocksd");
	return L;
}

static bool run_chunk(lua_State *restrict L, const char *restrict chunk)
{
	if (luaL_loadstring(L, chunk) != LUA_OK) {
		return false;
	}
	return lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK;
}

/* ---- tests ---- */

T_DECLARE_CASE(api_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "neosocksd");
	T_EXPECT(lua_istable(L, -1));

	const char *const fns[] = {
		"async",     "config",       "invoke",      "now",
		"parse_ipv4","parse_ipv6",   "resolve",     "setinterval",
		"splithostport","stats",     "traceback",
	};
	for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
		lua_getfield(L, -1, fns[i]);
		T_EXPECT(lua_isfunction(L, -1));
		lua_pop(L, 1);
	}

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv4_valid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return neosocksd.parse_ipv4('127.0.0.1')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0x7f000001);

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv4_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* each of these should return zero values */
	T_EXPECT(run_chunk(
		L, "local a = neosocksd.parse_ipv4('999.0.0.1') "
		   "local b = neosocksd.parse_ipv4('abc') "
		   "local c = neosocksd.parse_ipv4(nil) "
		   "return a, b, c"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT(lua_isnil(L, 1));
	T_EXPECT(lua_isnil(L, 2));
	T_EXPECT(lua_isnil(L, 3));

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv6_valid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* "::1" -> all-zeros high half, 1 in low half */
	T_EXPECT(run_chunk(L, "return neosocksd.parse_ipv6('::1')"));
#if LUA_32BITS
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 2), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 3), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 4), (lua_Integer)1);
#else
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 2), (lua_Integer)1);
#endif

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv6_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local a = neosocksd.parse_ipv6('::g') "
		   "local b = neosocksd.parse_ipv6(nil) "
		   "return a, b"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnil(L, 1));
	T_EXPECT(lua_isnil(L, 2));

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_simple)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "return neosocksd.splithostport('example.com:80')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_STREQ(lua_tostring(L, 1), "example.com");
	T_EXPECT_STREQ(lua_tostring(L, 2), "80");

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_ipv6)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "return neosocksd.splithostport('[::1]:443')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_STREQ(lua_tostring(L, 1), "::1");
	T_EXPECT_STREQ(lua_tostring(L, 2), "443");

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* missing port – must raise a Lua error caught by pcall */
	const int rc_load = luaL_loadstring(
		L,
		"local ok, err = pcall(neosocksd.splithostport, 'noport') "
		"return ok, err");
	T_EXPECT_EQ(rc_load, LUA_OK);
	const int rc_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(rc_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT(lua_type(L, 2) == LUA_TSTRING);

	lua_close(L);
}

T_DECLARE_CASE(api_traceback_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return neosocksd.traceback('boom')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	const char *restrict s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strstr(s, "boom") != NULL);

	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, api_module_opens);
	T_RUN_CASE(t, api_parse_ipv4_valid);
	T_RUN_CASE(t, api_parse_ipv4_invalid);
	T_RUN_CASE(t, api_parse_ipv6_valid);
	T_RUN_CASE(t, api_parse_ipv6_invalid);
	T_RUN_CASE(t, api_splithostport_simple);
	T_RUN_CASE(t, api_splithostport_ipv6);
	T_RUN_CASE(t, api_splithostport_invalid);
	T_RUN_CASE(t, api_traceback_string);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
