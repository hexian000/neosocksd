/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/cfunc.h"

#include "conf.h"
#include "ruleset/base.h"
#include "ruleset/ruleset.h"
#include "util.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MT_RULESET_STATE "ruleset_state"

/* Detach @p state from its callback and notify the event loop that the
 * asynchronous operation has finished. */
static void state_complete(lua_State *restrict L, struct ruleset_state *state)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	ev_feed_event(r->loop, &state->cb->w_finish, EV_CUSTOM);
	state->cb = NULL;
	/* Detach *selfptr synchronously: `state` becomes unreachable to Lua
	 * once this closure returns, so any GC before the fed event fires could
	 * free it, and ruleset_cancel() would then run on a dangling pointer. */
	if (state->selfptr != NULL && *state->selfptr == state) {
		*state->selfptr = NULL;
	}
}

static int ruleset_state_gc(lua_State *restrict L)
{
	struct ruleset_state *restrict state = lua_touserdata(L, 1);
	if (state->cb == NULL) {
		return 0;
	}
	/* This finalizer runs for both request and rpcall states; clearing
	 * rpcall.result also clears request.req, since both are the union's
	 * first member and share offset 0 (see struct ruleset_callback). */
	state->cb->rpcall.result = NULL;
	state->cb->rpcall.resultlen = 0;
	state_complete(L, state);
	return 0;
}

static void check_memlimit(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	const int_fast32_t memlimit_kb = r->config.memlimit_kb;
	if (memlimit_kb <= 0) {
		return;
	}
	if (lua_gc(L, LUA_GCCOUNT, 0) < memlimit_kb) {
		return;
	}
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
}

static struct ruleset_state *new_ruleset_state(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_newuserdata(L, sizeof(struct ruleset_state));
	*state = (struct ruleset_state){ 0 };
	if (luaL_newmetatable(L, MT_RULESET_STATE)) {
		lua_pushcfunction(L, ruleset_state_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	return state;
}

/* finish(ok, ...) */
static int request_finish(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	/* clear the forward context as the routine finishes */
	aux_setforward(L, L, NULL);
	if (state->cb == NULL) {
		return 0;
	}
	struct dialreq *req = NULL;
	if (lua_toboolean(L, 1)) {
		const int n = lua_gettop(L) - 1;
		if (n > 0 && aux_todialreq(L, n)) {
			req = lua_touserdata(L, -1);
		}
		if (req == NULL) {
			/* the routine gave up without forwarding: reject by policy */
			LOGD("ruleset: request rejected");
		}
	} else {
		LOGE_F("ruleset error: %s", luaL_tolstring(L, 2, NULL));
	}
	state->cb->request.req = req;
	state_complete(L, state);
	return 0;
}

/* request(state, func, request, username, password, callback) */
int cfunc_request(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 6);
	struct ruleset_state *restrict *restrict const pstate =
		(struct ruleset_state *restrict *restrict)lua_touserdata(L, 1);
	const char *const func = lua_touserdata(L, 2);
	const char *const request = lua_touserdata(L, 3);
	const char *const username = lua_touserdata(L, 4);
	const char *const password = lua_touserdata(L, 5);
	struct ruleset_callback *restrict const in_cb = lua_touserdata(L, 6);
	lua_settop(L, 0);

	struct ruleset_state *restrict state = new_ruleset_state(L);

	lua_pushvalue(L, 1);
	lua_pushcclosure(L, request_finish, 1);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_pushstring(L, request);
	lua_pushstring(L, username);
	lua_pushstring(L, password);
	/* lua stack: state finish ruleset func request username password */

	/* Check out the coroutine only after the fallible stack setup above:
	 * aux_getthread() increments num_thread_active and pulls a thread from
	 * the idle pool, and nothing before aux_async() would return it if an
	 * earlier step raised (e.g. LUA_ERRMEM from lua_pushstring). */
	lua_State *restrict co = aux_getthread(L);
	lua_insert(L, 2);
	/* lua stack: state co finish ruleset func request username password */

	state->cb = in_cb;
	*pstate = state;
	state->selfptr = (struct ruleset_state **)pstate;
	/* register the request for await.forward() */
	aux_setforward(L, co, state);
	const int status = aux_async(co, L, 3, -6);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_xmove(co, L, 1);
		return lua_error(L);
	}
	lua_settop(L, 1);
	return 1;
}

/* loadfile(stream) */
int cfunc_loadfile(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	struct stream *restrict const s = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (aux_load(L, s, "=ruleset")) {
		return lua_error(L);
	}
	lua_pushliteral(L, "ruleset");
	lua_call(L, 1, 1);
	lua_setglobal(L, "ruleset");
	return 0;
}

/* loadconfig() */
int cfunc_loadconfig(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	struct stream *restrict const s = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (aux_load(L, s, "=config")) {
		return lua_error(L);
	}
	lua_pushliteral(L, "config");
	if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
		return lua_error(L);
	}
	if (!lua_istable(L, -1)) {
		return luaL_error(
			L, "config: expected table, got %s",
			luaL_typename(L, -1));
	}

	/* extract `ruleset` table before conf_loadfromtable sees it */
	lua_getfield(L, -1, "ruleset");
	if (lua_istable(L, -1)) {
		lua_setglobal(L, "ruleset");
		lua_pushnil(L);
		lua_setfield(L, -2, "ruleset");
	} else if (!lua_isnil(L, -1)) {
		return luaL_error(
			L,
			"config: `ruleset' must be a table; use `-r' for a standalone ruleset file");
	} else {
		lua_pop(L, 1);
	}

	struct ruleset *restrict r = aux_getruleset(L);
	if (!conf_loadfromtable(L, r->conf)) {
		return luaL_error(L, "config: failed to load fields");
	}

	/* Extract memlimit and traceback into r->config */
	lua_getfield(L, -1, "memlimit");
	if (!lua_isnil(L, -1)) {
		/* memlimit is in MiB; keep the arithmetic in lua_Integer and reject
		 * values that would overflow the KiB field. Non-positive disables. */
		const lua_Integer mb = luaL_checkinteger(L, -1);
		if (mb > (INT_MAX >> 10)) {
			return luaL_error(L, "config: memlimit too large");
		}
		r->config.memlimit_kb =
			(mb > 0) ? (int_least32_t)(mb << 10) : 0;
	}
	lua_pop(L, 1);

	lua_getfield(L, -1, "traceback");
	if (!lua_isnil(L, -1)) {
		r->config.traceback = lua_toboolean(L, -1) != 0;
	}
	lua_pop(L, 1);

	return 0;
}

/* invoke(codestream) */
int cfunc_invoke(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	void *const stream = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (aux_load(L, stream, "=(invoke)")) {
		return lua_error(L);
	}
	aux_setsandboxenv(L);
	lua_call(L, 0, 0);
	return 0;
}

/* finish(ok, ...) */
static int rpcall_finish(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	if (state->cb == NULL) {
		return 0;
	}
	/* finish(ok, ...): a false ok means the rpc chunk raised, leaving
	 * (false, errmsg) on the stack. Surface that as an rpcall failure
	 * instead of marshalling it as a successful (false, "...") result. */
	if (!lua_toboolean(L, 1)) {
		LOGE_F("ruleset rpcall: %s", luaL_tolstring(L, 2, NULL));
		state->cb->rpcall.result = NULL;
		state->cb->rpcall.resultlen = 0;
		state_complete(L, state);
		return 0;
	}
	const int n = lua_gettop(L);
	lua_pushliteral(L, "return ");
	lua_getglobal(L, "marshal");
	lua_rotate(L, 1, 2);
	/* lua stack: "return " marshal ... */
	if (lua_pcall(L, n, 1, 0) != LUA_OK) {
		/* marshal() can raise (e.g. an unmarshalable type); report a failed
		 * result rather than letting the error escape and leave the
		 * caller's callback pending. */
		LOGE_F("ruleset rpcall: marshal failed: %s",
		       luaL_tolstring(L, -1, NULL));
		state->cb->rpcall.result = NULL;
		state->cb->rpcall.resultlen = 0;
		state_complete(L, state);
		return 0;
	}
	lua_concat(L, 2);
	size_t len;
	const char *s = lua_tolstring(L, 1, &len);
	/* Copy the marshalled result into a C-owned buffer: `s` borrows Lua
	 * memory freed once this closure returns, but rpcall_cb() reads it later
	 * from the deferred event. The consumer takes ownership and frees it. */
	char *result = malloc(len);
	if (result == NULL && len > 0) {
		LOGOOM();
		state->cb->rpcall.result = NULL;
		state->cb->rpcall.resultlen = 0;
		state_complete(L, state);
		return 0;
	}
	if (len > 0) {
		(void)memcpy(result, s, len);
	}
	state->cb->rpcall.result = result;
	state->cb->rpcall.resultlen = len;
	state_complete(L, state);
	return 0;
}

/* rpcall(state, codestream, callback) */
int cfunc_rpcall(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 3);
	struct ruleset_state *restrict *restrict const pstate =
		(struct ruleset_state *restrict *restrict)lua_touserdata(L, 1);
	struct stream *const stream = lua_touserdata(L, 2);
	struct ruleset_callback *restrict const in_cb = lua_touserdata(L, 3);
	lua_settop(L, 0);

	struct ruleset_state *restrict state = new_ruleset_state(L);

	lua_pushvalue(L, 1);
	lua_pushcclosure(L, rpcall_finish, 1);
	if (aux_load(L, stream, "=(rpc)")) {
		return lua_error(L);
	}
	/* lua stack: state finish chunk */
	aux_setsandboxenv(L);

	/* Check out the coroutine only after all fallible setup: aux_getthread()
	 * increments num_thread_active and removes a thread from the idle pool,
	 * but lua_load() (a client syntax error) and aux_setsandboxenv() may
	 * raise before aux_async(), and nothing on that early-error path would
	 * return the thread. */
	lua_State *restrict co = aux_getthread(L);
	lua_insert(L, 2);
	/* lua stack: state co finish chunk */

	state->cb = in_cb;
	*pstate = state;
	state->selfptr = (struct ruleset_state **)pstate;
	const int status = aux_async(co, L, 0, -2);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_xmove(co, L, 1);
		return lua_error(L);
	}
	lua_settop(L, 1);
	return 1;
}

#define LUA_LOADED_TABLE "_LOADED"

/* m = replace(modname, chunk) */
static int package_replace(lua_State *restrict L)
{
	const int idx_modname = 1;
	luaL_checktype(L, idx_modname, LUA_TSTRING);
	const int idx_openf = 2;
	luaL_checktype(L, idx_openf, LUA_TFUNCTION);
	lua_settop(L, 2);
	const int idx_loaded = 3;
	luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
	const int idx_glb = 4;
	aux_getregtable(L, LUA_RIDX_GLOBALS);

	int glb = 0;
	/* LOADED[modname] */
	lua_pushvalue(L, idx_modname);
	if (lua_gettable(L, idx_loaded) != LUA_TNIL) {
		lua_pushvalue(L, idx_modname);
		/* _G[modname] */
		lua_gettable(L, idx_glb);
		glb = lua_rawequal(L, -2, -1);
		lua_pop(L, 2);
	} else {
		lua_pop(L, 1);
	}
	/* open function */
	lua_pushvalue(L, idx_openf);
	/* argument to open function */
	lua_pushvalue(L, idx_modname);
	/* call open function */
	lua_call(L, 1, 1);
	/* modname */
	lua_pushvalue(L, idx_modname);
	if (!lua_isnil(L, -2)) {
		/* Make a copy of the module returned by the open function. */
		lua_pushvalue(L, -2);
	} else {
		/* No value returned, use true as the result. */
		lua_pushboolean(L, 1);
	}
	/* LOADED[modname] = module */
	lua_settable(L, idx_loaded);
	if (glb) {
		/* modname */
		lua_pushvalue(L, idx_modname);
		/* copy of module */
		lua_pushvalue(L, -2);
		/* _G[modname] = module */
		lua_settable(L, idx_glb);
	}
	return 1;
}

/* update(modname, chunkname, codestream) */
int cfunc_update(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 3);
	const char *modname = lua_touserdata(L, 1);
	const char *chunkname = lua_touserdata(L, 2);
	void *const stream = lua_touserdata(L, 3);
	lua_settop(L, 0);

	if (modname != NULL) {
		modname = lua_pushstring(L, modname);
	} else {
		modname = lua_pushliteral(L, "ruleset");
	}
	if (chunkname != NULL) {
		chunkname = lua_pushstring(L, chunkname);
	} else {
		chunkname = lua_pushfstring(L, "=%s", modname);
	}
	if (aux_load(L, stream, chunkname)) {
		return lua_error(L);
	}
	/* lua stack: modname chunkname chunk */
	if (strcmp(modname, "ruleset") == 0) {
		lua_pushvalue(L, 1);
		lua_call(L, 1, 1);
		if (!lua_istable(L, -1)) {
			/* the caller (/ruleset/update) does not re-check validity, so
			 * reject here rather than wire up a broken global ruleset */
			return luaL_error(
				L, "ruleset: expected table, got %s",
				luaL_typename(L, -1));
		}
		lua_setglobal(L, modname);
		return 0;
	}
	lua_pushcfunction(L, package_replace);
	lua_pushvalue(L, 1);
	lua_pushvalue(L, 3);
	lua_call(L, 2, 0);
	return 0;
}

/* Look up the ruleset[name] hook. If it is a function, leave it alone at
 * stack slot 1 (clearing everything else) and return true; otherwise clear
 * the stack and return false. */
static bool get_ruleset_hook(lua_State *restrict L, const char *name)
{
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, name);
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, 0);
		return false;
	}
	lua_replace(L, 1);
	lua_settop(L, 1);
	return true;
}

/* stats(dt, query) */
int cfunc_stats(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 2);
	const double dt = *(double *)lua_touserdata(L, 1);
	const char *const query = lua_touserdata(L, 2);
	if (!get_ruleset_hook(L, "stats")) {
		/* no hook: empty string (NULL = error) */
		lua_pushliteral(L, "");
		return 1;
	}
	lua_pushnumber(L, dt);
	lua_pushstring(L, query);
	lua_call(L, 2, 1);
	return 1;
}

/* metrics() */
int cfunc_metrics(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 0);
	if (!get_ruleset_hook(L, "metrics")) {
		return 0;
	}
	lua_call(L, 0, 1);
	return 1;
}

/* tick() */
int cfunc_tick(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 0);
	if (!get_ruleset_hook(L, "tick")) {
		return 0;
	}
	lua_call(L, 0, 0);
	return 0;
}

/* healthy() */
int cfunc_healthy(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 0);
	if (!get_ruleset_hook(L, "healthy")) {
		return 0; /* absent: healthy */
	}
	lua_call(L, 0, 1);
	return 1;
}

/* gc() */
int cfunc_gc(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 0);
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
	return 0;
}
