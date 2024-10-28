/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "cfunc.h"

#include "utils/debug.h"

#include "ruleset/base.h"
#include "ruleset/marshal.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

/* request(func, request, username, password) */
int cfunc_request(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 4);
	const char *func = lua_touserdata(L, 1);
	const char *request = lua_touserdata(L, 2);
	const char *username = lua_touserdata(L, 3);
	const char *password = lua_touserdata(L, 4);
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
	struct dialreq *req = aux_todialreq(L, n);
	if (req == NULL) {
		LOGW_F("ruleset.%s `%s': invalid return", func, request);
	}
	return 1;
}

/* loadfile(filename) */
int cfunc_loadfile(lua_State *restrict L)
{
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
	ASSERT(lua_gettop(L) == 1);
	void *stream = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (lua_load(L, aux_reader, stream, "=(invoke)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	/* lua stack: chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *upvalue = lua_setupvalue(L, -2, 1);
	CHECK(upvalue != NULL && CONSTSTREQUAL(upvalue, "_ENV"));
	lua_call(L, 0, 0);
	return 0;
}

static int rpcall_gc(lua_State *restrict L)
{
	struct rpcall_state *restrict state = lua_touserdata(L, 1);
	if (state->callback.func != NULL) {
		state->callback.func(state->callback.data, NULL, 0);
		state->callback.func = NULL;
	}
	return 0;
}

/* finish(ok, ...) */
static int rpcall_finish(lua_State *restrict L)
{
	struct rpcall_state *restrict state =
		lua_touserdata(L, lua_upvalueindex(1));
	if (state->callback.func == NULL) {
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
	state->callback.func(state->callback.data, s, len);
	state->callback.func = NULL;
	return 0;
}

#define MT_RPCALL "rpcall"

/* rpcall(codestream, callback, data) */
int cfunc_rpcall(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 2);
	struct stream *stream = lua_touserdata(L, 1);
	const struct rpcall_cb *in_cb = lua_touserdata(L, 2);
	struct rpcall_state *restrict state =
		lua_newuserdata(L, sizeof(struct rpcall_state));
	*state = (struct rpcall_state){ .callback = { NULL, NULL } };
	if (luaL_newmetatable(L, MT_RPCALL)) {
		lua_pushcfunction(L, rpcall_gc);
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
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	/* lua stack: state co chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *upvalue = lua_setupvalue(L, -2, 1);
	CHECK(upvalue != NULL && CONSTSTREQUAL(upvalue, "_ENV"));

	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_ASYNC_ROUTINE) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	lua_pushvalue(L, 2);
	lua_pushvalue(L, 1);
	lua_pushcclosure(L, rpcall_finish, 1);
	/* lua stack: state co chunk RIDX_ASYNC_ROUTINE co finish */
	lua_rawset(L, -3);
	lua_pop(L, 1);
	lua_xmove(L, co, 1);
	state->callback = *in_cb;
	/* lua stack: state co; co stack: chunk */
	aux_resume(L, 2, 0);
	lua_settop(L, 1);
	return 1;
}

#define LUA_LOADED_TABLE "_LOADED"

/* replace(modname, chunk) */
static int aux_package_replace(lua_State *restrict L)
{
	const int idx_modname = 1;
	luaL_checktype(L, idx_modname, LUA_TSTRING);
	const int idx_openf = 2;
	luaL_checktype(L, idx_openf, LUA_TFUNCTION);
	lua_settop(L, 2);
	const int idx_loaded = 3;
	luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
	const int idx_glb = 4;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}

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

/* update(modname, codestream, chunkname) */
int cfunc_update(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 3);
	const char *modname = lua_touserdata(L, 1);
	void *stream = lua_touserdata(L, 2);
	const char *chunkname = lua_touserdata(L, 3);
	lua_settop(L, 0);

	lua_pushstring(L, modname);
	if (chunkname == NULL) {
		const char *name = (modname != NULL) ? modname : "ruleset";
		const size_t namelen = strlen(name);
		char luaname[1 + namelen + 1];
		luaname[0] = '=';
		memcpy(luaname + 1, name, namelen);
		luaname[1 + namelen] = '\0';
		if (lua_load(L, aux_reader, stream, luaname, NULL)) {
			return lua_error(L);
		}
	} else {
		if (lua_load(L, aux_reader, stream, chunkname, NULL)) {
			return lua_error(L);
		}
	}
	if (modname == NULL) {
		lua_pushliteral(L, "ruleset");
		lua_call(L, 1, 1);
		lua_setglobal(L, "ruleset");
		return 0;
	}
	(void)aux_package_replace(L);
	return 0;
}

/* stats(func, dt) */
int cfunc_stats(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 2);
	const char *func = lua_touserdata(L, 1);
	const double dt = *(double *)lua_touserdata(L, 2);
	lua_settop(L, 0);

	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_replace(L, -2);
	lua_pushnumber(L, dt);
	lua_call(L, 1, 1);
	return 1;
}

/* tick(now) */
int cfunc_tick(lua_State *restrict L)
{
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
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
	return 0;
}
