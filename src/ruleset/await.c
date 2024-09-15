/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "await.h"

#include "base.h"
#include "compat.h"

#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include "api_client.h"
#include "conf.h"
#include "resolver.h"
#include "ruleset.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

#include <limits.h>
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
			lua_pushliteral((L), ERR_NOT_YIELDABLE);               \
			return lua_error((L));                                 \
		}                                                              \
	} while (0)

/* [-0, +0, m] */
static void context_pin(lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
	if (lua_pushthread(L)) {
		lua_pushliteral(L, ERR_NOT_YIELDABLE);
		lua_error(L);
	}
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
	find_ruleset(L)->vmstats.num_context++;
}

/* [-0, +0, m] */
static void context_unpin(lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
	lua_pushnil(L);
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
	find_ruleset(L)->vmstats.num_context--;
}

static int await_idle_gc_(struct lua_State *L)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_idle *w = lua_touserdata(L, 1);
	ev_idle_stop(r->loop, w);
	return 0;
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	if (!ruleset_resume(r, watcher, 0)) {
		LOGE_F("idle_cb: %s", ruleset_geterror(r, NULL));
	}
}

static int
await_idle_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	context_unpin(L, lua_touserdata(L, (int)ctx));
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return 0;
}

/* await.idle() */
static int await_idle_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	lua_settop(L, 0);

	struct ruleset *restrict r = find_ruleset(L);
	struct ev_idle *restrict w = lua_newuserdata(L, sizeof(struct ev_idle));
	ev_idle_init(w, idle_cb);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_IDLE)) {
		lua_pushcfunction(L, await_idle_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	const int ctx = lua_absindex(L, -1);
	context_pin(L, w);
	ev_idle_start(r->loop, w);
	const int status = lua_yieldk(L, 0, ctx, await_idle_k_);
	return await_idle_k_(L, status, ctx);
}

static int await_sleep_gc_(struct lua_State *L)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *w = lua_touserdata(L, 1);
	ev_timer_stop(r->loop, w);
	return 0;
}

static void
sleep_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	if (!ruleset_resume(r, watcher, 0)) {
		LOGE_F("sleep_cb: %s", ruleset_geterror(r, NULL));
	}
}

static int
await_sleep_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	context_unpin(L, lua_touserdata(L, (int)ctx));
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return 0;
}

/* await.sleep(n) */
static int await_sleep_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	lua_Number n = luaL_checknumber(L, 1);
	lua_settop(L, 1);

	if (!isnormal(n)) {
		return 0;
	}
	n = CLAMP(n, 1e-3, 1e+9);
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w =
		lua_newuserdata(L, sizeof(struct ev_timer));
	ev_timer_init(w, sleep_cb, n, 0.0);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_SLEEP)) {
		lua_pushcfunction(L, await_sleep_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	const int ctx = lua_absindex(L, -1);
	context_pin(L, w);
	ev_timer_start(r->loop, w);
	const int status = lua_yieldk(L, 0, ctx, await_sleep_k_);
	return await_sleep_k_(L, status, ctx);
}

static int await_resolve_close_(struct lua_State *L)
{
	handle_type *restrict h = lua_touserdata(L, 1);
	if (*h != INVALID_HANDLE) {
		resolve_cancel(*h);
		*h = INVALID_HANDLE;
	}
	return 0;
}

static void resolve_cb(
	handle_type h, struct ev_loop *loop, void *ctx,
	const struct sockaddr *sa)
{
	UNUSED(loop);
	struct ruleset *restrict r = ctx;
	const void *p = handle_toptr(h);
	if (!ruleset_resume(r, p, 1, (void *)sa)) {
		LOGE_F("resolve_cb: %s", ruleset_geterror(r, NULL));
	}
}

static int
await_resolve_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	handle_type *restrict p = lua_touserdata(L, (int)ctx);
	context_unpin(L, handle_toptr(*p));
	*p = INVALID_HANDLE;
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	return format_addr_(L);
}

/* await.resolve(host) */
static int await_resolve_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	const char *name = luaL_checkstring(L, 1);
	lua_settop(L, 1);

	const handle_type h = resolve_do(
		G.resolver,
		(struct resolve_cb){
			.cb = resolve_cb,
			.ctx = find_ruleset(L),
		},
		name, NULL, G.conf->resolve_pf);
	if (h == INVALID_HANDLE) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	handle_type *restrict p = lua_newuserdata(L, sizeof(handle_type));
	*p = h;
	if (luaL_newmetatable(L, MT_AWAIT_RESOLVE)) {
		lua_pushcfunction(L, await_resolve_close_);
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
	const int ctx = lua_absindex(L, -1);
	context_pin(L, handle_toptr(h));
	const int status = lua_yieldk(L, 0, ctx, await_resolve_k_);
	return await_resolve_k_(L, status, ctx);
}

static int await_invoke_close_(struct lua_State *L)
{
	handle_type *h = lua_touserdata(L, 1);
	if (*h != INVALID_HANDLE) {
		struct ruleset *restrict r = find_ruleset(L);
		api_cancel(r->loop, *h);
		*h = INVALID_HANDLE;
	}
	return 0;
}

static void invoke_cb(
	handle_type h, struct ev_loop *loop, void *ctx, bool ok,
	const void *data, size_t len)
{
	UNUSED(loop);
	struct ruleset *restrict r = ctx;
	const void *p = handle_toptr(h);
	if (!ruleset_resume(r, p, 3, (void *)&ok, (void *)data, (void *)&len)) {
		LOGE_F("invoke_cb: %s", ruleset_geterror(r, NULL));
	}
}

static int
await_invoke_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	handle_type *restrict p = lua_touserdata(L, (int)ctx);
	context_unpin(L, handle_toptr(*p));
	*p = INVALID_HANDLE;
	if (status != LUA_OK && status != LUA_YIELD) {
		return lua_error(L);
	}
	const bool ok = *(bool *)lua_touserdata(L, -3);
	const void *data = lua_touserdata(L, -2);
	const size_t len = *(size_t *)lua_touserdata(L, -1);
	lua_settop(L, 0);

	if (!ok) {
		lua_pushboolean(L, 0);
		lua_pushlstring(L, data, len);
		return 2;
	}
	/* unmarshal */
	struct reader_status rd = {
		.s = (struct stream *)data,
		.prefix = "return ",
		.prefixlen = 7,
	};
	if (lua_load(L, ruleset_reader, &rd, "=(unmarshal)", NULL)) {
		return lua_error(L);
	}
	lua_newtable(L);
	/* lua stack: ok chunk env */
	if (lua_setupvalue(L, -2, -1) == NULL) {
		lua_pop(L, 1);
	}
	lua_call(L, 0, LUA_MULTRET);
	return lua_gettop(L);
}

/* ok, ... = await.invoke(code, addr, proxyN, ..., proxy1) */
static int await_invoke_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L);
	for (int i = 2; i <= MAX(2, n); i++) {
		luaL_checktype(L, i, LUA_TSTRING);
	}
	struct dialreq *req = pop_dialreq_(L, n - 1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ROUTE);
		return lua_error(L);
	}
	struct ruleset *restrict r = find_ruleset(L);
	struct api_client_cb cb = {
		.func = invoke_cb,
		.ctx = r,
	};
	handle_type h =
		api_invoke(r->loop, req, "/ruleset/rpcall", code, len, cb);
	if (h == INVALID_HANDLE) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	lua_pop(L, 1); /* code */
	handle_type *restrict p = lua_newuserdata(L, sizeof(handle_type));
	*p = h;
	if (luaL_newmetatable(L, MT_AWAIT_INVOKE)) {
		lua_pushcfunction(L, await_invoke_close_);
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
	const int ctx = lua_absindex(L, -1);
	context_pin(L, handle_toptr(h));
	const int status = lua_yieldk(L, 0, ctx, await_invoke_k_);
	return await_invoke_k_(L, status, ctx);
}

int luaopen_await(lua_State *restrict L)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_newtable(L);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	}
	const luaL_Reg awaitlib[] = {
		{ "resolve", await_resolve_ },
		{ "invoke", await_invoke_ },
		{ "sleep", await_sleep_ },
		{ "idle", await_idle_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, awaitlib);
	return 1;
}
