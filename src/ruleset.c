/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file ruleset.c
 * @brief Implementation of Lua-based ruleset engine
 */

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

/**
 * @brief Custom memory allocator for Lua virtual machine
 *
 * This allocator tracks memory usage statistics and provides memory
 * accounting for the ruleset engine. It wraps standard malloc/free/realloc
 * functions while maintaining counters for allocated objects and bytes.
 *
 * @param ud User data (ruleset instance)
 * @param ptr Pointer to existing memory block (NULL for allocation)
 * @param osize Old size of memory block
 * @param nsize New size of memory block (0 for deallocation)
 * @return Pointer to allocated/reallocated memory, or NULL
 */
static void *
l_alloc(void *ud, void *ptr, const size_t osize, const size_t nsize)
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

/**
 * @brief Lua panic handler
 * @param L Lua state
 * @return Always returns 0
 */
static int l_panic(lua_State *L)
{
	const char *msg = (lua_type(L, -1) == LUA_TSTRING) ?
				  lua_tostring(L, -1) :
				  "error object is not a string";
	LOG_STACK_F(
		FATAL, 0, "PANIC: unprotected error in call to Lua API (%s)",
		msg);
	return 0; /* return to Lua to abort */
}

/**
 * @brief Initialize Lua environment for ruleset
 *
 * Sets up the Lua virtual machine with necessary registry tables,
 * standard libraries, and built-in extensions. This includes:
 * - Constant strings table for error messages
 * - Await context table for asynchronous operations
 * - Idle thread table for thread management
 * - Standard Lua libraries with restricted package paths
 * - Built-in extension libraries (await, marshal, regex, etc.)
 *
 * @param L Lua state to initialize
 * @return Always returns 0
 */
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

/**
 * @brief Timer callback for periodic ruleset operations
 *
 * This callback is invoked periodically (every second) to trigger
 * maintenance operations in the Lua ruleset. It starts an idle watcher
 * to defer the actual work to avoid blocking the event loop.
 *
 * @param loop Event loop
 * @param watcher Timer watcher that triggered
 * @param revents Event flags (should be EV_TIMER)
 */
static void tick_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct ruleset *restrict r = watcher->data;
	ev_idle_start(loop, &r->w_idle);
}

/**
 * @brief Idle callback for deferred ruleset tick processing
 *
 * This callback performs the actual periodic maintenance work for the
 * ruleset. It calls the Lua ruleset.tick() function with the current
 * timestamp, allowing the script to perform housekeeping tasks.
 *
 * @param loop Event loop
 * @param watcher Idle watcher that triggered
 * @param revents Event flags (should be EV_IDLE)
 */
static void idle_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	struct ruleset *restrict r = watcher->data;
	if (r->w_ticker.repeat > 0) {
		ev_idle_stop(loop, watcher);
	}
	const bool ok = ruleset_pcall(r, cfunc_tick, 0, 0);
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

	/* initialize in advance to prevent undefined behavior */
	ev_timer_init(&r->w_ticker, tick_cb, 1.0, 1.0);
	r->w_ticker.data = r;
	ev_idle_init(&r->w_idle, idle_cb);
	r->w_idle.data = r;

	lua_State *restrict L =
#if LUA_VERSION_NUM >= 505
		lua_newstate(l_alloc, r, luaL_makeseed(NULL));
#else
		lua_newstate(l_alloc, r);
#endif
	if (L == NULL) {
		free(r);
		return NULL;
	}
	(void)lua_atpanic(L, l_panic);
	r->L = L;

	lua_gc(L, LUA_GCSTOP, 0);
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
	lua_gc(L, LUA_GCRESTART, 0);
#if LUA_VERSION_NUM >= 504
	lua_gc(L, LUA_GCGEN, 0, 0);
#endif
	return r;
}

void ruleset_free(struct ruleset *restrict r)
{
	if (r == NULL) {
		return;
	}
	ev_timer_stop(r->loop, &r->w_ticker);
	ev_idle_stop(r->loop, &r->w_idle);
	lua_close(r->L);
	free(r);
}

/**
 * @brief Macro to create constant length string
 *
 * Helper macro that returns a constant string and optionally sets its length.
 * Used for efficient string literals with known lengths.
 */
#define CONST_LSTRING(s, len)                                                  \
	((len) != NULL ? (*(len) = sizeof(s) - 1, "" s) : ("" s))

const char *
ruleset_geterror(const struct ruleset *restrict r, size_t *restrict len)
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

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	if (state->cb != NULL) {
		ev_clear_pending(loop, &state->cb->w_finish);
	}
	state->cb = NULL;
}

bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct stream *code, struct ruleset_callback *callback)
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
	const char *password, struct ruleset_callback *callback)
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
	struct ruleset_callback *callback)
{
	return dispatch_request(
		r, state, "resolve", request, username, password, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	struct ruleset_callback *callback)
{
	return dispatch_request(
		r, state, "route", request, username, password, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	struct ruleset_callback *callback)
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
