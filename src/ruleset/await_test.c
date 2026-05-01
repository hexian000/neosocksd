/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/await.h"

#include "ruleset/base.h"

#include "api_client.h"
#include "dialer.h"
#include "resolver.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * await.c and base.c are included as sources.  The stubs below satisfy
 * their external symbol dependencies.  The tested functions (sleep,
 * resolve, invoke, execute) check lua_isyieldable() first; calling them
 * from the main thread causes an immediate lua_error() before any
 * dialer/resolver/api_client operation is attempted.
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

/* ---- resolver stubs (required by await.c's await_resolve) ---- */

struct resolve_query *resolve_do(
	struct resolver *restrict r, const struct resolve_cb cb,
	const char *restrict name, const char *restrict service,
	const int family)
{
	(void)r;
	(void)cb;
	(void)name;
	(void)service;
	(void)family;
	return NULL;
}

void resolve_cancel(struct resolve_query *q)
{
	(void)q;
}

/* ---- api_client stubs (required by await.c's await_invoke) ---- */

bool api_client_rpcall(
	struct ev_loop *restrict loop,
	struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const void *restrict payload,
	size_t len, const struct api_client_cb *restrict cb,
	const struct config *conf, struct resolver *resolver)
{
	(void)loop;
	(void)pctx;
	(void)req;
	(void)payload;
	(void)len;
	(void)cb;
	(void)conf;
	(void)resolver;
	return false;
}

void api_client_cancel(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx)
{
	(void)loop;
	(void)ctx;
}

/* ---- Lua helpers ---- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_await(L);
	lua_setglobal(L, "await");
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

T_DECLARE_CASE(await_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "await");
	T_EXPECT(lua_istable(L, -1));

	const char *const fns[] = { "sleep", "resolve", "invoke", "execute" };
	for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
		lua_getfield(L, -1, fns[i]);
		T_EXPECT(lua_isfunction(L, -1));
		lua_pop(L, 1);
	}

	lua_close(L);
}

T_DECLARE_CASE(await_sleep_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* pcall captures the error thrown by AWAIT_CHECK_YIELDABLE */
	T_EXPECT(run_chunk(
		L,
		"local ok, err = pcall(await.sleep, 0) "
		"return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_resolve_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local ok, err = pcall(await.resolve, 'example.com') "
		"return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(await_invoke_rejects_non_coroutine)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local ok, err = pcall(await.invoke, 'return 1', '127.0.0.1:1') "
		"return ok, err"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	const char *restrict err = lua_tostring(L, 2);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, "not in asynchronous routine") != NULL);

	lua_close(L);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, await_module_opens);
	T_RUN_CASE(t, await_sleep_rejects_non_coroutine);
	T_RUN_CASE(t, await_resolve_rejects_non_coroutine);
	T_RUN_CASE(t, await_invoke_rejects_non_coroutine);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
