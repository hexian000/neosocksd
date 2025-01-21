/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "await.h"

#include "base.h"

#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include "api_client.h"
#include "conf.h"
#include "resolver.h"
#include "sockutil.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>
#include <unistd.h>

#include <math.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MT_AWAIT_SLEEP "await.sleep"
#define MT_AWAIT_RESOLVE "await.resolve"
#define MT_AWAIT_INVOKE "await.invoke"
#define MT_AWAIT_EXECUTE "await.execute"

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
	aux_getregtable(L, RIDX_AWAIT_CONTEXT);
	if (lua_pushthread(L)) {
		lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
		lua_error(L);
		return;
	}
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
}

/* [-0, +0, -] */
static void context_unpin(lua_State *restrict L, const void *p)
{
	aux_getregtable(L, RIDX_AWAIT_CONTEXT);
	lua_pushnil(L);
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
}

struct await_sleep_userdata {
	struct ruleset *ruleset;
	struct ev_timer w_timer;
	struct ev_idle w_idle;
};

static int await_sleep_close(lua_State *restrict L)
{
	struct await_sleep_userdata *ud = lua_touserdata(L, 1);
	struct ev_loop *loop = ud->ruleset->loop;
	ev_timer_stop(loop, &ud->w_timer);
	ev_idle_stop(loop, &ud->w_idle);
	context_unpin(L, ud);
	return 0;
}

static void
sleep_cb(struct ev_loop *loop, struct ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct await_sleep_userdata *restrict ud = watcher->data;
	ev_idle_start(loop, &ud->w_idle);
}

static void sleep_finish_cb(
	struct ev_loop *loop, struct ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_sleep_userdata *restrict ud = watcher->data;
	ruleset_resume(ud->ruleset, ud, 1, NULL);
}

static int
await_sleep_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	CHECK(status == LUA_YIELD);
	const int base = (int)ctx;
	ASSERT(lua_gettop(L) == base + 1);
	struct await_sleep_userdata *restrict ud = lua_touserdata(L, base);
	context_unpin(L, ud);
	const char *err = lua_touserdata(L, base + 1);
	if (err != NULL) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	return 0;
}

/* await.sleep(n) */
static int await_sleep(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	lua_Number n = luaL_checknumber(L, 1);
	luaL_argcheck(L, isfinite(n) && 0 <= n && n <= 1e+9, 1, NULL);
	lua_settop(L, 1);
	struct ruleset *restrict r = aux_getruleset(L);
	struct await_sleep_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_sleep_userdata));
	ud->ruleset = r;
	ev_timer_init(&ud->w_timer, sleep_cb, n, 0.0);
	ud->w_timer.data = ud;
	ev_idle_init(&ud->w_idle, sleep_finish_cb);
	ud->w_idle.data = ud;
	if (luaL_newmetatable(L, MT_AWAIT_SLEEP)) {
#if HAVE_LUA_TOCLOSE
		lua_pushcfunction(L, await_sleep_close);
		lua_setfield(L, -2, "__close");
#endif
		lua_pushcfunction(L, await_sleep_close);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	context_pin(L, ud);
	if (n > 0) {
		ev_timer_start(r->loop, &ud->w_timer);
	} else {
		ev_idle_start(r->loop, &ud->w_idle);
	}
	lua_yieldk(L, 0, lua_gettop(L), await_sleep_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_resolve_userdata {
	struct ruleset *ruleset;
	struct resolve_query *query;
	struct ev_idle w_idle;
	union sockaddr_max sa;
};

static int await_resolve_close(lua_State *restrict L)
{
	struct await_resolve_userdata *ud = lua_touserdata(L, 1);
	if (ud->query != NULL) {
		resolve_cancel(ud->query);
		ud->query = NULL;
	}
	ev_idle_stop(ud->ruleset->loop, &ud->w_idle);
	context_unpin(L, ud);
	return 0;
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *data,
	const struct sockaddr *sa)
{
	struct await_resolve_userdata *ud = data;
	ASSERT(ud->query == q);
	ud->query = NULL;
	copy_sa(&ud->sa.sa, sa);
	ev_idle_start(loop, &ud->w_idle);
}

static void resolve_finish_cb(
	struct ev_loop *loop, struct ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_resolve_userdata *restrict ud = watcher->data;
	const struct sockaddr *sa = &ud->sa.sa;
	ruleset_resume(ud->ruleset, ud, 2, NULL, (void *)sa);
}

static int
await_resolve_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	CHECK(status == LUA_YIELD);
	const int base = (int)ctx;
	struct await_resolve_userdata *ud = lua_touserdata(L, base);
	context_unpin(L, ud);
	const char *err = lua_touserdata(L, base + 1);
	if (err != NULL) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	ASSERT(lua_gettop(L) == base + 2);
	return aux_format_addr(L);
}

/* await.resolve(host) */
static int await_resolve(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	const char *name = luaL_checkstring(L, 1);
	lua_settop(L, 1);
	struct await_resolve_userdata *ud =
		lua_newuserdata(L, sizeof(struct await_resolve_userdata));
	ud->ruleset = aux_getruleset(L);
	ud->query = NULL;
	ev_idle_init(&ud->w_idle, resolve_finish_cb);
	ud->w_idle.data = ud;
	if (luaL_newmetatable(L, MT_AWAIT_RESOLVE)) {
#if HAVE_LUA_TOCLOSE
		lua_pushcfunction(L, await_resolve_close);
		lua_setfield(L, -2, "__close");
#endif
		lua_pushcfunction(L, await_resolve_close);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	ud->query = resolve_do(
		G.resolver,
		(struct resolve_cb){
			.func = resolve_cb,
			.data = ud,
		},
		name, NULL, G.conf->resolve_pf);
	if (ud->query == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	context_pin(L, ud);
	lua_yieldk(L, 0, lua_gettop(L), await_resolve_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_invoke_userdata {
	struct ruleset *ruleset;
	struct api_client_ctx *ctx;
};

static int await_invoke_close(lua_State *restrict L)
{
	struct await_invoke_userdata *restrict ud = lua_touserdata(L, 1);
	if (ud->ctx != NULL) {
		struct ruleset *restrict r = aux_getruleset(L);
		api_client_cancel(r->loop, ud->ctx);
		ud->ctx = NULL;
	}
	context_unpin(L, ud);
	return 0;
}

static void invoke_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const char *err, const size_t errlen, struct stream *stream)
{
	UNUSED(loop);
	struct await_invoke_userdata *restrict ud = data;
	ASSERT(ud->ctx == ctx);
	ud->ctx = NULL;
	ruleset_resume(
		ud->ruleset, ud, 4, NULL, (void *)err, (void *)&errlen,
		(void *)stream);
}

static int
await_invoke_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	CHECK(status == LUA_YIELD);
	const int base = (int)ctx;
	struct await_invoke_userdata *restrict ud = lua_touserdata(L, base);
	context_unpin(L, ud);
	const char *err = lua_touserdata(L, base + 1);
	if (err != NULL) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	ASSERT(lua_gettop(L) == base + 4);
	const char *errmsg = lua_touserdata(L, base + 2);
	const size_t errlen = *(size_t *)lua_touserdata(L, base + 3);
	struct stream *stream = lua_touserdata(L, base + 4);
	lua_pushboolean(L, errmsg == NULL);
	if (errmsg != NULL) {
		lua_pushlstring(L, errmsg, errlen);
		return 2;
	}
	if (lua_load(L, aux_reader, (void *)stream, "=(rpc)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	aux_getregtable(L, LUA_RIDX_GLOBALS);
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
	lua_settop(L, 1);
	/* lua stack: code */
	struct ruleset *restrict r = aux_getruleset(L);
	struct await_invoke_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_invoke_userdata));
	*ud = (struct await_invoke_userdata){
		.ruleset = r,
		.ctx = NULL,
	};
	if (luaL_newmetatable(L, MT_AWAIT_INVOKE)) {
#if HAVE_LUA_TOCLOSE
		lua_pushcfunction(L, await_invoke_close);
		lua_setfield(L, -2, "__close");
#endif
		lua_pushcfunction(L, await_invoke_close);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	const struct api_client_cb cb = {
		.func = invoke_cb,
		.data = ud,
	};
	const bool ok =
		api_client_rpcall(r->loop, &ud->ctx, req, code, len, &cb);
	if (!ok) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	context_pin(L, ud);
	lua_yieldk(L, 0, lua_gettop(L), await_invoke_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_execute_userdata {
	struct ruleset *ruleset;
	struct ev_child w_child;
	struct ev_idle w_idle;
};

static int await_execute_close(lua_State *restrict L)
{
	struct await_execute_userdata *restrict ud = lua_touserdata(L, 1);
	const pid_t pid = ud->w_child.pid;
	struct ev_loop *loop = ud->ruleset->loop;
	ev_child_stop(loop, &ud->w_child);
	ev_idle_stop(loop, &ud->w_idle);
	if (pid > 0) {
		if (kill(pid, SIGKILL) != 0) {
			LOGE_F("kill: %s", strerror(errno));
		}
		ud->w_child.pid = 0;
	}
	context_unpin(L, ud);
	return 0;
}

static void
child_cb(struct ev_loop *loop, struct ev_child *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CHILD);
	ev_child_stop(loop, watcher);
	watcher->pid = 0;
	struct await_execute_userdata *restrict ud = watcher->data;
	ev_idle_start(loop, &ud->w_idle);
}

static void child_finish_cb(
	struct ev_loop *loop, struct ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_execute_userdata *restrict ud = watcher->data;
	ruleset_resume(ud->ruleset, ud, 1, NULL);
}

static int
await_execute_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	CHECK(status == LUA_YIELD);
	const int base = (int)ctx;
	struct await_execute_userdata *restrict ud = lua_touserdata(L, base);
	context_unpin(L, ud);
	const char *err = lua_touserdata(L, base + 1);
	if (err != NULL) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	ASSERT(lua_gettop(L) == base + 1);
	lua_pushinteger(L, ud->w_child.rstatus);
	return 0;
}

/* status = await.execute(command) */
static int await_execute(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *command = luaL_checklstring(L, 1, &len);
	lua_settop(L, 1);

	struct ruleset *restrict r = aux_getruleset(L);
	struct await_execute_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_execute_userdata));
	ud->ruleset = r;
	ev_child_init(&ud->w_child, child_cb, 0, 0);
	ud->w_child.data = ud;
	ev_idle_init(&ud->w_idle, child_finish_cb);
	ud->w_idle.data = ud;
	if (luaL_newmetatable(L, MT_AWAIT_EXECUTE)) {
#if HAVE_LUA_TOCLOSE
		lua_pushcfunction(L, await_execute_close);
		lua_setfield(L, -2, "__close");
#endif
		lua_pushcfunction(L, await_execute_close);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif

	pid_t pid = fork();
	if (pid < 0) {
		const char *err = strerror(errno);
		lua_pushstring(L, err);
		return lua_error(L);
	}
	if (pid == 0) {
		if (setsid() < 0) {
			LOGW_F("setsid: %s", strerror(errno));
		}
		const char *argv[] = { "sh", "-c", command, NULL };
		execv("/bin/sh", (char **)argv);
		FAILMSGF("execv: %s", strerror(errno));
	}
	ev_child_set(&ud->w_child, pid, 0);
	ud->w_child.data = ud;
	ev_child_start(r->loop, &ud->w_child);

	context_pin(L, ud);
	lua_yieldk(L, 0, lua_gettop(L), await_execute_k);
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
		{ "execute", await_execute },
		{ "invoke", await_invoke },
		{ "resolve", await_resolve },
		{ "sleep", await_sleep },
		{ NULL, NULL },
	};
	luaL_newlib(L, awaitlib);
	return 1;
}
