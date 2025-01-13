/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "cfunc.h"

#include "base.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "ruleset.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

#include <stddef.h>
#include <string.h>

#define MT_RULESET_STATE "ruleset_state"

static int ruleset_state_gc(lua_State *restrict L)
{
	struct ruleset_state *restrict state = lua_touserdata(L, 1);
	switch (state->type) {
	case RCB_REQUEST:
		if (state->request.func != NULL) {
			struct ruleset *r = aux_getruleset(L);
			state->request.func(r->loop, state->request.data, NULL);
			state->request.func = NULL;
		}
		break;
	case RCB_RPCALL:
		if (state->rpcall.func != NULL) {
			state->rpcall.func(state->rpcall.data, NULL, 0);
			state->rpcall.func = NULL;
		}
		break;
	default:
		FAIL();
	}
	return 0;
}

static void check_memlimit(lua_State *restrict L)
{
	struct ruleset *restrict r = aux_getruleset(L);
	const int memlimit_kb = r->memlimit_kb;
	if (memlimit_kb <= 0) {
		return;
	}
	if (lua_gc(L, LUA_GCCOUNT, 0) < memlimit_kb) {
		return;
	}
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
}

/* request(func, request, username, password) */
int cfunc_request(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 5);
	const char *func = lua_touserdata(L, 1);
	const char *request = lua_touserdata(L, 2);
	const char *username = lua_touserdata(L, 3);
	const char *password = lua_touserdata(L, 4);
	const struct ruleset_request_cb *in_cb = lua_touserdata(L, 5);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_copy(L, -1, 1);
	lua_settop(L, 1);

	lua_pushstring(L, request);
	lua_pushstring(L, username);
	lua_pushstring(L, password);
	lua_call(L, 3, LUA_MULTRET);
	const int n = lua_gettop(L);
	if (n < 1) {
		return 0;
	}
	if (!aux_todialreq(L, n)) {
		LOGW_F("ruleset.%s `%s': invalid return", func, request);
		in_cb->func(in_cb->loop, in_cb->data, NULL);
		return 0;
	}
	in_cb->func(in_cb->loop, in_cb->data, lua_touserdata(L, -1));
	return 1;
}

/* loadfile(filename) */
int cfunc_loadfile(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	const char *filename = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (luaL_loadfile(L, filename)) {
		return lua_error(L);
	}
	lua_pushliteral(L, "ruleset");
	lua_call(L, 1, 1);
	lua_setglobal(L, "ruleset");
	return 0;
}

/* invoke(codestream) */
int cfunc_invoke(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	void *stream = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (lua_load(L, aux_reader, stream, "=(invoke)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	aux_getregtable(L, LUA_RIDX_GLOBALS);
	/* lua stack: chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *upvalue = lua_setupvalue(L, -2, 1);
	CHECK(upvalue != NULL && strcmp(upvalue, "_ENV") == 0);
	lua_call(L, 0, 0);
	return 0;
}

/* finish(ok, ...) */
static int rpcall_finish(lua_State *restrict L)
{
	struct ruleset_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	if (state->rpcall.func == NULL) {
		return 0;
	}
	const int n = lua_gettop(L);
	lua_pushliteral(L, "return ");
	lua_getglobal(L, "marshal");
	lua_rotate(L, 1, 2);
	/* lua stack: "return " marshal ... */
	lua_call(L, n, 1);
	lua_concat(L, 2);
	size_t len;
	const char *s = lua_tolstring(L, 1, &len);
	state->rpcall.func(state->rpcall.data, s, len);
	state->rpcall.func = NULL;
	return 0;
}

/* rpcall(codestream, callback, data) */
int cfunc_rpcall(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 2);
	struct stream *stream = lua_touserdata(L, 1);
	const struct ruleset_rpcall_cb *in_cb = lua_touserdata(L, 2);
	struct ruleset_state *restrict state =
		lua_newuserdata(L, sizeof(struct ruleset_state));
	*state = (struct ruleset_state){
		.type = RCB_RPCALL,
		.rpcall = { NULL, NULL },
	};
	if (luaL_newmetatable(L, MT_RULESET_STATE)) {
		lua_pushcfunction(L, ruleset_state_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	lua_copy(L, -1, 1);
	lua_settop(L, 1);

	lua_State *restrict co = lua_newthread(L);
	if (lua_load(L, aux_reader, stream, "=(rpc)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	aux_getregtable(L, LUA_RIDX_GLOBALS);
	/* lua stack: state co chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *upvalue = lua_setupvalue(L, -2, 1);
	CHECK(upvalue != NULL && strcmp(upvalue, "_ENV") == 0);

	aux_getregtable(L, RIDX_ASYNC_ROUTINE);
	lua_pushvalue(L, 2);
	lua_pushvalue(L, 1);
	lua_pushcclosure(L, rpcall_finish, 1);
	/* lua stack: state co chunk RIDX_ASYNC_ROUTINE co finish */
	lua_rawset(L, -3);
	lua_pop(L, 1);
	lua_xmove(L, co, 1);
	state->rpcall = *in_cb;
	/* lua stack: state co; co stack: chunk */
	aux_resume(L, 2, 0);
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
		lua_gettable(L, idx_glb); /* _G[modname] */
		glb = lua_rawequal(L, -2, -1);
		lua_pop(L, 2);
	} else {
		lua_pop(L, 1);
	}
	lua_pushvalue(L, idx_openf); /* open function */
	lua_pushvalue(L, idx_modname); /* argument to open function */
	lua_call(L, 1, 1); /* call open function */
	lua_pushvalue(L, idx_modname); /* modname */
	if (!lua_isnil(L, -2)) {
		lua_pushvalue(L, -2); /* make copy of module (call result) */
	} else {
		lua_pushboolean(L, 1); /* no value, use true as result */
	}
	lua_settable(L, idx_loaded); /* LOADED[modname] = module */
	if (glb) {
		lua_pushvalue(L, idx_modname); /* modname */
		lua_pushvalue(L, -2); /* copy of module */
		lua_settable(L, idx_glb); /* _G[modname] = module */
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
	void *stream = lua_touserdata(L, 3);
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
	if (lua_load(L, aux_reader, stream, chunkname, NULL)) {
		return lua_error(L);
	}
	/* lua stack: modname chunkname chunk */
	if (strcmp(modname, "ruleset") == 0) {
		lua_pushvalue(L, 1);
		lua_call(L, 1, 1);
		lua_setglobal(L, modname);
		return 0;
	}
	lua_pushcfunction(L, package_replace);
	lua_pushvalue(L, 1);
	lua_pushvalue(L, 3);
	lua_call(L, 2, 0);
	return 0;
}

/* stats(dt, query) */
int cfunc_stats(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 2);
	const double dt = *(double *)lua_touserdata(L, 1);
	const char *query = lua_touserdata(L, 2);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, "stats");
	lua_copy(L, -1, 1);
	lua_settop(L, 1);

	lua_replace(L, -2);
	lua_pushnumber(L, dt);
	lua_pushstring(L, query);
	lua_call(L, 2, 1);
	return 1;
}

/* tick(now) */
int cfunc_tick(lua_State *restrict L)
{
	check_memlimit(L);
	ASSERT(lua_gettop(L) == 1);
	const ev_tstamp now = *(ev_tstamp *)lua_touserdata(L, 1);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, "tick");
	lua_copy(L, -1, 1);
	lua_settop(L, 1);

	lua_pushnumber(L, now);
	lua_call(L, 1, 0);
	return 0;
}

/* gc() */
int cfunc_gc(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 0);
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
	return 0;
}
