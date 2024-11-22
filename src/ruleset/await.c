/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "await.h"

#include "utils/debug.h"
#include "utils/minmax.h"

#include "api_client.h"
#include "conf.h"
#include "resolver.h"
#include "ruleset/base.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

#include <math.h>
#include <stdbool.h>
#include <stddef.h>

#define MT_AWAIT_IDLE "await.idle"
#define MT_AWAIT_SLEEP "await.sleep"
#define MT_AWAIT_RESOLVE "await.resolve"
#define MT_AWAIT_INVOKE "await.invoke"

#define AWAIT_CHECK_YIELDABLE(L)                                               \
	do {                                                                   \
		if (!lua_isyieldable((L))) {                                   \
			lua_pushliteral((L), ERR_NOT_ASYNC_ROUTINE);           \
			return lua_error((L));                                 \
		}                                                              \
	} while (0)

#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)

/* [-0, +0, m] */
static void context_pin(lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
		return;
	}
	if (lua_pushthread(L)) {
		lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
		lua_error(L);
		return;
	}
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
	aux_getruleset(L)->vmstats.num_context++;
}

/* [-0, +0, -] */
static void context_unpin(lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
		return;
	}
	lua_pushnil(L);
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
	aux_getruleset(L)->vmstats.num_context--;
}

static int await_idle_gc(struct lua_State *restrict L)
{
	struct ruleset *restrict r = aux_getruleset(L);
	struct ev_idle *w = lua_touserdata(L, 1);
	ev_idle_stop(r->loop, w);
	return 0;
}

static void
idle_cb(struct ev_loop *loop, struct ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct ruleset *r = watcher->data;
	ruleset_resume(r, watcher, 0);
}

static int
await_idle_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	context_unpin(L, lua_touserdata(L, (int)ctx));
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return 0;
}

/* await.idle() */
static int await_idle(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	struct ruleset *restrict r = aux_getruleset(L);
	struct ev_idle *restrict w = lua_newuserdata(L, sizeof(struct ev_idle));
	ev_idle_init(w, idle_cb);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_IDLE)) {
		lua_pushcfunction(L, await_idle_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	const lua_KContext ctx = lua_absindex(L, -1);
	context_pin(L, w);
	ev_idle_start(r->loop, w);
	lua_yieldk(L, 0, ctx, await_idle_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

static int await_sleep_gc(struct lua_State *restrict L)
{
	struct ruleset *restrict r = aux_getruleset(L);
	struct ev_timer *w = lua_touserdata(L, 1);
	ev_timer_stop(r->loop, w);
	return 0;
}

static void
sleep_cb(struct ev_loop *loop, struct ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct ruleset *r = watcher->data;
	ruleset_resume(r, watcher, 0);
}

static int
await_sleep_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	context_unpin(L, lua_touserdata(L, (int)ctx));
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return 0;
}

/* await.sleep(n) */
static int await_sleep(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	lua_Number n = luaL_checknumber(L, 1);
	if (!isnormal(n)) {
		return 0;
	}
	n = CLAMP(n, 1e-3, 1e+9);
	struct ruleset *restrict r = aux_getruleset(L);
	struct ev_timer *restrict w =
		lua_newuserdata(L, sizeof(struct ev_timer));
	ev_timer_init(w, sleep_cb, n, 0.0);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_SLEEP)) {
		lua_pushcfunction(L, await_sleep_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	const lua_KContext ctx = lua_absindex(L, -1);
	context_pin(L, w);
	ev_timer_start(r->loop, w);
	lua_yieldk(L, 0, ctx, await_sleep_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

static int await_resolve_close(struct lua_State *restrict L)
{
	struct resolve_query **ud = lua_touserdata(L, 1);
	if (*ud != NULL) {
		resolve_cancel(*ud);
		*ud = NULL;
	}
	return 0;
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *data,
	const struct sockaddr *sa)
{
	UNUSED(loop);
	struct ruleset *r = data;
	ruleset_resume(r, q, 1, (void *)sa);
}

static int
await_resolve_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	struct resolve_query **ud = lua_touserdata(L, (int)ctx);
	context_unpin(L, *ud);
	*ud = NULL;
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return aux_format_addr(L);
}

/* await.resolve(host) */
static int await_resolve(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	const char *name = luaL_checkstring(L, 1);
	struct resolve_query *q = resolve_do(
		G.resolver,
		(struct resolve_cb){
			.func = resolve_cb,
			.data = aux_getruleset(L),
		},
		name, NULL, G.conf->resolve_pf);
	if (q == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	struct resolve_query **ud =
		lua_newuserdata(L, sizeof(struct resolve_query *));
	*ud = q;
	if (luaL_newmetatable(L, MT_AWAIT_RESOLVE)) {
		lua_pushcfunction(L, await_resolve_close);
#if HAVE_LUA_TOCLOSE
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, "__close");
#endif
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	const lua_KContext ctx = lua_absindex(L, -1);
	context_pin(L, q);
	lua_yieldk(L, 0, ctx, await_resolve_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

static int await_invoke_close(struct lua_State *restrict L)
{
	struct api_client_ctx **ud = lua_touserdata(L, 1);
	if (*ud != NULL) {
		struct ruleset *restrict r = aux_getruleset(L);
		api_client_cancel(r->loop, *ud);
		*ud = NULL;
	}
	return 0;
}

static void invoke_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const bool ok, const void *payload, const size_t len)
{
	UNUSED(loop);
	struct ruleset *r = data;
	ruleset_resume(r, ctx, 3, (void *)&ok, (void *)payload, (void *)&len);
}

static int
await_invoke_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	struct api_client_ctx **ud = lua_touserdata(L, (int)ctx);
	context_unpin(L, *ud);
	*ud = NULL;
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	const bool ok = *(bool *)lua_touserdata(L, -3);
	const void *payload = lua_touserdata(L, -2);
	const size_t len = *(size_t *)lua_touserdata(L, -1);
	lua_pushboolean(L, ok);
	if (!ok) {
		lua_pushlstring(L, payload, len);
		return 2;
	}
	if (lua_load(L, aux_reader, (void *)payload, "=(rpc)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	/* lua stack: ok chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *upvalue = lua_setupvalue(L, -2, 1);
	CHECK(upvalue != NULL && strcmp(upvalue, "_ENV") == 0);
	return 2;
}

/* ok, ... = await.invoke(code, addr, proxyN, ..., proxy1) */
static int await_invoke(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L) - 1;
	if (!aux_todialreq(L, n)) {
		lua_pushliteral(L, ERR_INVALID_INVOKE);
		return lua_error(L);
	}
	struct dialreq *req = lua_touserdata(L, -1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_INVOKE);
		return lua_error(L);
	}
	struct ruleset *restrict r = aux_getruleset(L);
	struct api_client_cb cb = {
		.func = invoke_cb,
		.data = r,
	};
	struct api_client_ctx *apictx =
		api_client_rpcall(r->loop, req, code, len, cb);
	if (apictx == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	/* lua stack: code dialreq */
	lua_pop(L, 2);
	struct api_client_ctx **ud =
		lua_newuserdata(L, sizeof(struct api_client_ctx *));
	*ud = apictx;
	if (luaL_newmetatable(L, MT_AWAIT_INVOKE)) {
		lua_pushcfunction(L, await_invoke_close);
#if HAVE_LUA_TOCLOSE
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, "__close");
#endif
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	const lua_KContext ctx = lua_absindex(L, -1);
	context_pin(L, apictx);
	lua_yieldk(L, 0, ctx, await_invoke_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

int luaopen_await(lua_State *restrict L)
{
	lua_newtable(L); /* async routine */
	lua_newtable(L); /* mt */
	lua_pushliteral(L, "k");
	lua_setfield(L, -2, "__mode");
	lua_setmetatable(L, -2);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_ASYNC_ROUTINE);
	lua_newtable(L); /* await context */
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	const luaL_Reg awaitlib[] = {
		{ "resolve", await_resolve },
		{ "invoke", await_invoke },
		{ "sleep", await_sleep },
		{ "idle", await_idle },
		{ NULL, NULL },
	};
	luaL_newlib(L, awaitlib);
	return 1;
}
