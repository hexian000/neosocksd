/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "cfunc.h"

#include "base.h"
#include "conf.h"
#include "ruleset.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>

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

/* Force a full collection once the VM is at its memory limit. The limit is
 * judged against the allocator's total rather than LUA_GCCOUNT: lauxlib's
 * string buffers allocate through the allocator without entering Lua's own
 * count, and on Lua 5.5 the strings built from them stay outside it. */
static void check_memlimit(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	const int_fast32_t memlimit_kb = r->config.memlimit_kb;
	if (memlimit_kb <= 0) {
		return;
	}
	if ((r->vmstats.byt_allocated >> 10) < (size_t)memlimit_kb) {
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

/* Protected wrapper around aux_todialreq: leaves the built dialreq as a
 * lightuserdata on top, NULL for a nil or invalid address (both reject the
 * request). Called through a pcall so a raise while converting args cannot
 * escape and orphan the op. */
static int protected_todialreq(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	if (aux_todialreq(L, n)) {
		return 1;
	}
	lua_pushlightuserdata(L, NULL);
	return 1;
}

/* Build the dialreq a successful routine returned, from the results above
 * finish's leading `ok`; NULL rejects the request. */
static struct dialreq *request_todialreq(lua_State *restrict L)
{
	const int n = lua_gettop(L) - 1;
	struct dialreq *req = NULL;
	if (n > 0) {
		/* aux_todialreq converts args with lua_tolstring, which can
		 * raise LUA_ERRMEM on a number arg; build under a pcall so such
		 * a raise cannot precede state_complete and orphan the async
		 * op. */
		lua_pushcfunction(L, protected_todialreq);
		lua_rotate(L, 2, 1);
		/* lua stack: ok protected_todialreq arg1 ... argN */
		if (lua_pcall(L, n, 1, 0) == LUA_OK) {
			req = lua_touserdata(L, -1);
		}
	}
	if (req == NULL) {
		/* the routine gave up without forwarding: reject by policy */
		LOGD("ruleset: request rejected");
	}
	return req;
}

/* finish(ok, ...) */
static int request_finish(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	/* clear the forward context as the routine finishes */
	aux_setforward(L, L, NULL);
	const bool ok = lua_toboolean(L, 1);
	/* A NULL callback means the consumer is gone -- the client cancelled, or
	 * await.forward() already committed the request -- so there is nothing
	 * to deliver, but an error the routine raised is still reported below. */
	if (state->cb != NULL) {
		struct dialreq *req = NULL;
		if (ok) {
			req = request_todialreq(L);
		}
		state->cb->request.req = req;
		state_complete(L, state);
	}
	if (!ok) {
		/* log the error only after completing: rendering the error
		 * object runs its __tostring, which must not observe a
		 * half-finished op */
		LOGE_F("ruleset error: %s", aux_errmsg(L, 2));
	}
	return 0;
}

/* Push a credential field as the exact bytes received, or nil if unsupplied. */
static void
push_credential(lua_State *restrict L, const char *s, const size_t len)
{
	if (s == NULL) {
		lua_pushnil(L);
		return;
	}
	(void)lua_pushlstring(L, s, len);
}

/* request(state, func, request, credentials, callback) */
int cfunc_request(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 5);
	struct ruleset_state *restrict *restrict const pstate =
		(struct ruleset_state *restrict *restrict)lua_touserdata(L, 1);
	const char *const func = lua_touserdata(L, 2);
	const char *const request = lua_touserdata(L, 3);
	const struct ruleset_credentials nocreds = { 0 };
	const struct ruleset_credentials *creds = lua_touserdata(L, 4);
	if (creds == NULL) {
		creds = &nocreds;
	}
	struct ruleset_callback *restrict const in_cb = lua_touserdata(L, 5);
	lua_settop(L, 0);

	struct ruleset_state *restrict state = new_ruleset_state(L);

	lua_pushvalue(L, 1);
	lua_pushcclosure(L, request_finish, 1);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_pushstring(L, request);
	push_credential(L, creds->username, creds->username_len);
	push_credential(L, creds->password, creds->password_len);
	/* lua stack: state finish ruleset func request username password */

	/* Check out the coroutine only after the fallible stack setup above:
	 * aux_getthread() increments num_thread_active and pulls a thread from
	 * the idle pool, and nothing before aux_async() would return it if an
	 * earlier step raised (e.g. LUA_ERRMEM while pushing a string). */
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
	struct io_stream *restrict const s = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (aux_load(L, s, "=ruleset")) {
		return lua_error(L);
	}
	lua_pushliteral(L, "ruleset");
	lua_call(L, 1, 1);
	if (!lua_istable(L, -1)) {
		/* a non-table result would install a broken global ruleset that
		 * only fails later per-request; reject it now, like cfunc_update */
		return luaL_error(
			L, "ruleset: expected table, got %s",
			luaL_typename(L, -1));
	}
	lua_setglobal(L, "ruleset");
	return 0;
}

/* Protected separately so a global-table __newindex or allocation failure
 * can discard the staged C config before the error is propagated. */
static int install_ruleset(lua_State *restrict L)
{
	lua_setglobal(L, "ruleset");
	return 0;
}

/* Shared body of loadconfig() and reloadconfig(). */
static int loadconfig(lua_State *restrict L, const bool reload)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	struct io_stream *restrict const s = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (aux_load(L, s, "=config")) {
		return lua_error(L);
	}
	lua_pushliteral(L, "config");
	lua_call(L, 1, 1);
	if (!lua_istable(L, -1)) {
		return luaL_error(
			L, "config: expected table, got %s",
			luaL_typename(L, -1));
	}

	/* Validate everything and stage the ruleset-local settings before touching
	 * any live state, so a bad field -- a config-field error from
	 * conf_loadfromtable, a too-large memlimit, or a non-table ruleset --
	 * fails the load without having replaced the global ruleset table or the
	 * config. The final config commit follows the fallible global installation.
	 * The config table stays on top for conf_loadfromtable. */
	struct ruleset *restrict r = aux_getruleset(L);

	/* stage memlimit (MiB -> KiB); an absent value keeps the current one */
	int_least32_t new_memlimit_kb = r->config.memlimit_kb;
	lua_getfield(L, 1, "memlimit");
	if (!lua_isnil(L, -1)) {
		/* keep the arithmetic in lua_Integer and reject values that would
		 * overflow the KiB field. Non-positive disables the limit. */
		if (!lua_isinteger(L, -1)) {
			return luaL_error(
				L,
				"config: field `memlimit' must be an integer");
		}
		const lua_Integer mb = lua_tointeger(L, -1);
		if (mb > (INT_LEAST32_MAX >> 10)) {
			return luaL_error(L, "config: memlimit too large");
		}
		new_memlimit_kb = (mb > 0) ? (int_least32_t)(mb << 10) : 0;
	}
	lua_pop(L, 1);

	/* stage traceback */
	bool new_traceback = r->config.traceback;
	lua_getfield(L, 1, "traceback");
	if (!lua_isnil(L, -1)) {
		new_traceback = lua_toboolean(L, -1) != 0;
	}
	lua_pop(L, 1);

	/* validate the `ruleset` table and remove it from the config table so
	 * conf_loadfromtable never sees it; keep its value on the stack to install
	 * after the staged config validates */
	lua_getfield(L, 1, "ruleset");
	const bool has_ruleset = lua_istable(L, -1);
	if (!has_ruleset && !lua_isnil(L, -1)) {
		return luaL_error(
			L,
			"config: `ruleset' must be a table; use `-r' for a standalone ruleset file");
	}
	if (has_ruleset) {
		lua_pushnil(L);
		lua_setfield(L, 1, "ruleset");
	}
	/* a reload installs no ruleset of its own when the table carries none,
	 * but keeps the one in place */
	bool will_have_ruleset = has_ruleset;
	if (reload && !has_ruleset) {
		will_have_ruleset = (lua_getglobal(L, "ruleset") == LUA_TTABLE);
		lua_pop(L, 1);
	}
	/* stack: 1=config table, 2=ruleset value; move the ruleset value below so
	 * the config table is back on top for conf_loadfromtable */
	lua_insert(L, 1);

	/* Preserve the old string block while the loader copies its referenced
	 * fields into a replacement owned by the staged config. Reserve the
	 * installation call's stack before that C allocation exists. */
	luaL_checkstack(L, 5, "config installation");
	/* Anchor the global key before allocating the staged string block. */
	lua_pushliteral(L, "ruleset");
	lua_insert(L, 1);
	/* stack: key, ruleset value, config table */
	struct config staged = *r->conf;
	staged.strings = NULL;
	const bool ok =
		reload ? conf_reloadfromtable(L, &staged, will_have_ruleset) :
			 conf_loadfromtable(L, &staged);
	if (!ok) {
		return luaL_error(L, "config: failed to load fields");
	}
	lua_pop(L, 1); /* config table: key and ruleset value remain */

	/* Install the global before changing live C state; lua_setglobal may
	 * invoke __newindex or allocate even though every field was validated. */
	if (has_ruleset) {
		lua_pushglobaltable(L);
		lua_pushvalue(L, 1);
		lua_rawget(L, 3);
		lua_rotate(L, 1, 2);
		/* stack: globals, old value, key, proposed ruleset */
		lua_pushcfunction(L, install_ruleset);
		lua_insert(L, 4);
		if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
			/* A raising __newindex may already have stored the new
			 * field. Restore its prior raw value without invoking it
			 * again; removing that new field does not allocate. */
			lua_pushvalue(L, 3);
			lua_pushvalue(L, 2);
			lua_rawset(L, 1);
			free(staged.strings);
			return lua_error(L);
		}
	} else {
		lua_pop(L, 1);
	}
	free(r->conf->strings);
	*r->conf = staged;
	r->config.memlimit_kb = new_memlimit_kb;
	r->config.traceback = new_traceback;
	return 0;
}

/* loadconfig() */
int cfunc_loadconfig(lua_State *restrict L)
{
	return loadconfig(L, false);
}

/* reloadconfig() */
int cfunc_reloadconfig(lua_State *restrict L)
{
	return loadconfig(L, true);
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

/* Protected: build "return " .. marshal(...) as a single Lua string on top,
 * running every fallible step (lua_pushliteral, lua_getglobal, marshal,
 * lua_concat) inside one pcall so an OOM/marshal raise is caught by the caller
 * rather than escaping rpcall_finish and orphaning the async op. */
static int build_rpcall_result(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	lua_pushliteral(L, "return ");
	lua_getglobal(L, "marshal");
	lua_rotate(L, 1, 2);
	/* lua stack: "return " marshal ... */
	lua_call(L, n, 1);
	lua_concat(L, 2);
	return 1;
}

/* finish(ok, ...) */
static int rpcall_finish(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	/* finish(ok, ...): a false ok means the rpc chunk raised, leaving
	 * (false, errmsg) on the stack. Surface that as an rpcall failure
	 * instead of marshalling it as a successful (false, "...") result. */
	if (!lua_toboolean(L, 1)) {
		/* a NULL callback means the client is gone: there is no failure
		 * to deliver, but the error is still reported */
		if (state->cb != NULL) {
			state->cb->rpcall.result = NULL;
			state->cb->rpcall.resultlen = 0;
			state_complete(L, state);
		}
		/* log after completing: rendering the error object runs its
		 * __tostring, which must not observe a half-finished op */
		LOGE_F("ruleset rpcall: %s", aux_errmsg(L, 2));
		return 0;
	}
	if (state->cb == NULL) {
		/* the client is gone: nobody reads the result */
		return 0;
	}
	const int n = lua_gettop(L);
	lua_pushcfunction(L, build_rpcall_result);
	lua_insert(L, 1);
	/* lua stack: build_rpcall_result ok ... */
	if (lua_pcall(L, n, 1, 0) != LUA_OK) {
		/* result-building (marshal, concat, OOM) can raise; report a failed
		 * result rather than letting the error escape and leave the
		 * caller's callback pending. */
		state->cb->rpcall.result = NULL;
		state->cb->rpcall.resultlen = 0;
		state_complete(L, state);
		/* log after completing: rendering the error object runs its
		 * __tostring, which must not observe a half-finished op */
		LOGE_F("ruleset rpcall: %s", aux_errmsg(L, -1));
		return 0;
	}
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);
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
	struct io_stream *const stream = lua_touserdata(L, 2);
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
	if (lua_isnil(L, -1)) {
		/* No value returned: use true as the module, so that LOADED, _G
		 * and the result all agree. */
		lua_pop(L, 1);
		lua_pushboolean(L, 1);
	}
	/* modname */
	lua_pushvalue(L, idx_modname);
	/* copy of module */
	lua_pushvalue(L, -2);
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
 * the stack and return false. A ruleset global that is not a table has no
 * hooks rather than being an error: ruleset_isvalid() gates it at load time
 * only, and ruleset Lua may replace it at any point afterwards. */
static bool get_ruleset_hook(lua_State *restrict L, const char *name)
{
	if (lua_getglobal(L, "ruleset") != LUA_TTABLE) {
		lua_settop(L, 0);
		return false;
	}
	(void)lua_getfield(L, -1, name);
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, 0);
		return false;
	}
	lua_replace(L, 1);
	lua_settop(L, 1);
	return true;
}

/* Call the hook on slot 1 with the @p nargs arguments above it and leave its
 * result on top. A number result is converted to its string form here, while
 * still protected: the conversion allocates, and the C caller reads the result
 * with lua_tolstring() after the protected call has returned. */
static int call_hook_tostring(lua_State *restrict L, const int nargs)
{
	lua_call(L, nargs, 1);
	(void)lua_tolstring(L, -1, NULL);
	return 1;
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
	return call_hook_tostring(L, 2);
}

/* metrics() */
int cfunc_metrics(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 0);
	if (!get_ruleset_hook(L, "metrics")) {
		return 0;
	}
	return call_hook_tostring(L, 0);
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
	return call_hook_tostring(L, 0);
}

/* isvalid() */
int cfunc_isvalid(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 0);
	/* honours _G's metatable, whose __index may raise */
	lua_pushboolean(L, lua_getglobal(L, "ruleset") == LUA_TTABLE);
	return 1;
}

/* gc() */
int cfunc_gc(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 0);
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
	return 0;
}
