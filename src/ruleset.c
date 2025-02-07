/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset.h"

#if WITH_RULESET

#include "conf.h"
#include "util.h"

#include "ruleset/api.h"
#include "ruleset/await.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
#include "ruleset/marshal.h"
#include "ruleset/regex.h"
#include "ruleset/time.h"
#include "ruleset/zlib.h"

#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct ruleset *restrict r = ud;
	if (nsize == 0) {
		/* free */
		if (ptr == NULL) {
			return NULL;
		}
		free(ptr);
		r->vmstats.byt_allocated -= osize;
		r->vmstats.num_object--;
		return NULL;
	}
	if (ptr == NULL) {
		/* malloc */
		void *ret = malloc(nsize);
		if (ret == NULL) {
			return NULL;
		}
		r->vmstats.num_object++;
		r->vmstats.byt_allocated += nsize;
		return ret;
	}
	/* realloc */
	void *ret = realloc(ptr, nsize);
	if (ret == NULL) {
		return NULL;
	}
	r->vmstats.byt_allocated = r->vmstats.byt_allocated - osize + nsize;
	return ret;
}

static int l_panic(lua_State *L)
{
	const int type = lua_type(L, -1);
	switch (type) {
	case LUA_TNIL:
		LOG_STACK(FATAL, 0, "panic: (nil)");
		break;
	case LUA_TSTRING:
		LOG_STACK_F(FATAL, 0, "panic: %s", lua_tostring(L, -1));
		break;
	default:
		LOG_STACK_F(
			FATAL, 0, "panic: (%s: %p)", lua_typename(L, type),
			lua_topointer(L, -1));
	}
	return 0; /* return to Lua to abort */
}

static int ruleset_luainit(lua_State *restrict L)
{
	/* init registry */
	const char *strings[] = {
		ERR_MEMORY,
		ERR_BAD_REGISTRY,
		ERR_INVALID_INVOKE,
		ERR_NOT_ASYNC_ROUTINE,
	};
	const int nstrings = (int)ARRAY_SIZE(strings);
	lua_createtable(L, nstrings, 0);
	for (int i = 0; i < nstrings; i++) {
		lua_pushstring(L, strings[i]);
		lua_rawseti(L, -2, i + 1);
	}
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_CONSTANT);
	lua_newtable(L); /* await context */
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	aux_newweaktable(L, "k"); /* idle threads */
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	/* load Lua libraries */
	luaL_openlibs(L);
	/* restrict package searcher */
	lua_getglobal(L, "package");
	lua_pushliteral(L, "?.lua");
	lua_setfield(L, -2, "path");
	lua_pushliteral(L, "?.so");
	lua_setfield(L, -2, "cpath");
	lua_pop(L, 1);
	/* load built-in libraries */
	const luaL_Reg libs[] = {
		{ "await", luaopen_await },
		{ "marshal", luaopen_marshal },
		{ "neosocksd", luaopen_neosocksd },
		{ "regex", luaopen_regex },
		{ "time", luaopen_time },
		{ "zlib", luaopen_zlib },
		{ NULL, NULL },
	};
	for (const luaL_Reg *lib = libs; lib->func; lib++) {
		luaL_requiref(L, lib->name, lib->func, 1);
		lua_pop(L, 1);
	}
	return 0;
}

static void tick_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct ruleset *restrict r = watcher->data;
	ev_idle_start(loop, &r->w_idle);
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	const ev_tstamp now = ev_now(loop);
	const bool ok = ruleset_pcall(r, cfunc_tick, 1, 0, &now);
	if (!ok) {
		LOGW_F("ruleset.tick: %s", ruleset_geterror(r, NULL));
		return;
	}
}

struct ruleset *ruleset_new(struct ev_loop *loop)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	r->loop = loop;
	r->vmstats = (struct ruleset_vmstats){ 0 };
	const int memlimit_mb = G.conf->memlimit;
	r->config.memlimit_kb = (memlimit_mb > 0) ? (memlimit_mb << 10u) : 0;
	r->config.traceback = !!G.conf->traceback;
	lua_State *restrict L = lua_newstate(l_alloc, r);
	if (L == NULL) {
		free(r);
		return NULL;
	}
	(void)lua_atpanic(L, l_panic);
	r->L = L;

	/* initialize in advance to prevent undefined behavior */
	ev_timer_init(&r->w_ticker, tick_cb, 1.0, 1.0);
	r->w_ticker.data = r;
	ev_idle_init(&r->w_idle, idle_cb);
	r->w_idle.data = r;

	lua_pushcfunction(L, ruleset_luainit);
	switch (lua_pcall(L, 0, 0, 0)) {
	case LUA_OK:
		break;
	case LUA_ERRMEM:
		ruleset_free(r);
		return NULL;
	default:
		FAILMSGF("ruleset init: %s", lua_tostring(L, -1));
	}
	return r;
}

void ruleset_free(struct ruleset *restrict r)
{
	if (r == NULL) {
		return;
	}
	ev_timer_stop(r->loop, &r->w_ticker);
	lua_close(r->L);
	free(r);
}

#define CONST_LSTRING(s, len)                                                  \
	((len) != NULL ? (*(len) = sizeof(s) - 1, "" s) : ("" s))

const char *ruleset_geterror(struct ruleset *restrict r, size_t *len)
{
	lua_State *restrict L = r->L;
	const char *s = NULL;
	switch (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR)) {
	case LUA_TNIL:
		s = CONST_LSTRING("(nil)", len);
		break;
	case LUA_TSTRING:
		s = lua_tolstring(L, -1, len);
		break;
	default:
		s = CONST_LSTRING("(error object is not a string)", len);
		break;
	}
	lua_pop(L, 1);
	return s;
}

bool ruleset_invoke(struct ruleset *restrict r, struct stream *code)
{
	return ruleset_pcall(r, cfunc_invoke, 1, 0, code);
}

void ruleset_cancel(struct ruleset_state *state)
{
	switch (state->type) {
	case RCB_REQUEST:
		state->request.func = NULL;
		break;
	case RCB_RPCALL:
		state->rpcall.func = NULL;
		break;
	default:
		FAIL();
	}
}

bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct stream *code, const struct ruleset_rpcall_cb *callback)
{
	return ruleset_pcall(r, cfunc_rpcall, 3, 1, state, code, callback);
}

bool ruleset_update(
	struct ruleset *restrict r, const char *modname, const char *chunkname,
	struct stream *code)
{
	return ruleset_pcall(r, cfunc_update, 3, 0, modname, chunkname, code);
}

bool ruleset_loadfile(struct ruleset *restrict r, const char *filename)
{
	return ruleset_pcall(r, cfunc_loadfile, 1, 0, filename);
}

bool ruleset_gc(struct ruleset *restrict r)
{
	return ruleset_pcall(r, cfunc_gc, 0, 0);
}

static bool dispatch_request(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *func, const char *request, const char *username,
	const char *password, const struct ruleset_request_cb *callback)
{
	lua_State *restrict L = r->L;
	const bool ok = ruleset_pcall(
		r, cfunc_request, 6, 1, (void *)state, (void *)func,
		(void *)request, (void *)username, (void *)password,
		(void *)callback);
	if (!ok) {
		LOGW_F("ruleset.%s: %s", func, ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_touserdata(L, -1);
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback)
{
	return dispatch_request(
		r, state, "resolve", request, username, password, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback)
{
	return dispatch_request(
		r, state, "route", request, username, password, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback)
{
	return dispatch_request(
		r, state, "route6", request, username, password, callback);
}

void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s)
{
	*s = r->vmstats;
}

const char *ruleset_stats(
	struct ruleset *restrict r, const double dt, const char *query,
	size_t *len)
{
	lua_State *restrict L = r->L;
	const bool ok =
		ruleset_pcall(r, cfunc_stats, 2, 1, (void *)&dt, (void *)query);
	if (!ok) {
		LOGW_F("ruleset.stats: %s", ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_tolstring(L, -1, len);
}

#endif /* WITH_RULESET */
