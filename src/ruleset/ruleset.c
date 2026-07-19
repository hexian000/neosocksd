/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/ruleset.h"

#if WITH_RULESET

#include "conf.h"
#include "dialer.h"
#include "proto/codec.h"
#include "resolver.h"
#include "ruleset/api.h"
#include "ruleset/await.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
#include "ruleset/marshal.h"
#include "ruleset/regex.h"
#include "ruleset/time.h"
#include "ruleset/zlib.h"
#include "util.h"

#include "io/stream.h"
#include "utils/debug.h"
#if WITH_ALLOC_CACHE
#include "utils/mcache.h"
#endif
#include "utils/slog.h"

#include <ev.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* defer ruleset.tick() to the idle watcher */
static void tick_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct ruleset *restrict r = watcher->data;
	ev_idle_start(loop, &r->w_idle);
}

static void idle_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	struct ruleset *restrict r = watcher->data;
	/*
	 * Negative interval intentionally keeps idle watcher active so
	 * ruleset.tick runs on each idle iteration.
	 */
	if (r->w_ticker.repeat > 0) {
		ev_idle_stop(loop, watcher);
	}
	const bool ok = ruleset_pcall(r, cfunc_tick, 0, 0);
	if (!ok) {
		LOGW_F("ruleset.tick: %s", ruleset_geterror(r, NULL));
		return;
	}
}

static void *
l_alloc(void *ud, void *ptr, const size_t osize, const size_t nsize)
{
	struct ruleset *restrict r = ud;
#if WITH_ALLOC_CACHE
	struct mmcache *restrict cache = r->vmcache;
	if (nsize == 0) {
		/* free */
		if (ptr == NULL) {
			return NULL;
		}
		mmcache_put(cache, ptr, osize);
		r->vmstats.byt_allocated -= osize;
		r->vmstats.num_object--;
		return NULL;
	}
	if (ptr == NULL) {
		/* malloc; osize is the object type tag here, not a size */
		void *ret = mmcache_get(cache, nsize);
		if (ret == NULL) {
			return NULL;
		}
		r->vmstats.num_object++;
		r->vmstats.byt_allocated += nsize;
		return ret;
	}
	/* realloc */
	const size_t oldshift = mmcache_shift(cache, osize);
	const size_t newshift = mmcache_shift(cache, nsize);
	void *ret;
	if (oldshift == newshift && newshift <= cache->max_shift) {
		/* same size class: the existing block already fits */
		ret = ptr;
	} else {
		/* Grow to class size, not nsize — preserves per-class invariant for mmcache_put(). */
		size_t newsize;
		if (newshift <= cache->max_shift) {
			newsize = (size_t)1 << newshift;
		} else {
			newsize = nsize;
		}
		ret = realloc(ptr, newsize);
		if (ret == NULL) {
			return NULL;
		}
	}
	r->vmstats.byt_allocated = r->vmstats.byt_allocated - osize + nsize;
	return ret;
#else /* WITH_ALLOC_CACHE */
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
		/* malloc; osize is the object type tag here, not a size */
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
#endif /* WITH_ALLOC_CACHE */
}

static int l_panic(lua_State *L)
{
	const char *msg;
	if (lua_type(L, -1) == LUA_TSTRING) {
		msg = lua_tostring(L, -1);
	} else {
		msg = "error object is not a string";
	}
	LOG_STACK_F(
		FATAL, 0, "PANIC: unprotected error in call to Lua API (%s)",
		msg);
	return 0;
}

static int ruleset_luainit(lua_State *restrict L)
{
	/* await context */
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	/* idle threads */
	aux_newweaktable(L, "k");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	/* forward context: thread pointer -> request state lightuserdata */
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_FORWARD_CONTEXT);
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

struct ruleset *ruleset_new(
	struct ev_loop *restrict loop, struct config *restrict conf,
	struct resolver *restrict resolver, struct dialreq *restrict basereq)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	r->loop = loop;
	r->vmstats = (struct ruleset_vmstats){ 0 };
	int memlimit_mb = conf->memlimit;
	if (memlimit_mb > (INT_MAX >> 10)) {
		/* clamp to avoid signed overflow in the MiB->KiB shift: conf.c and
		 * cfunc_loadconfig reject such values, but conf_loadfromtable's
		 * generic validator does not, so a poisoned conf could reach here */
		memlimit_mb = INT_MAX >> 10;
	}
	r->config.memlimit_kb =
		(memlimit_mb > 0) ? (int_least32_t)(memlimit_mb << 10) : 0;
	r->config.traceback = !!conf->traceback;
	r->conf = conf;
	r->resolver = resolver;
	r->server = NULL;
	r->basereq = basereq;

#if WITH_ALLOC_CACHE
	/* cache freed blocks in [16, 256] bytes to cut allocator churn */
	r->vmcache = mmcache_new(4, 8, 16);
	if (r->vmcache == NULL) {
		free(r);
		return NULL;
	}
#endif

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
#if WITH_ALLOC_CACHE
		mmcache_free(r->vmcache);
#endif
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

void ruleset_setserver(struct ruleset *restrict r, struct server *restrict s)
{
	r->server = s;
}

void ruleset_setbasereq(
	struct ruleset *restrict r, struct dialreq *restrict basereq)
{
	r->basereq = basereq;
}

void ruleset_free(struct ruleset *restrict r)
{
	if (r == NULL) {
		return;
	}
	ev_timer_stop(r->loop, &r->w_ticker);
	ev_idle_stop(r->loop, &r->w_idle);
	lua_close(r->L);
#if WITH_ALLOC_CACHE
	mmcache_free(r->vmcache);
#endif
	free(r);
}

/* return a string literal and optionally set its length */
#define CONST_LSTRING(s, len)                                                  \
	((len) != NULL ? (*(len) = sizeof(s) - 1, "" s) : ("" s))

const char *
ruleset_geterror(const struct ruleset *restrict r, size_t *restrict len)
{
	lua_State *restrict const L = r->L;
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
	return ruleset_pcall(r, cfunc_invoke, 1, 0, (void *)code);
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	if (state == NULL) {
		return;
	}
	if (state->cb != NULL) {
		ev_clear_pending(loop, &state->cb->w_finish);
	}
	state->cb = NULL;
}

bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct stream *code, struct ruleset_callback *callback)
{
	return ruleset_pcall(
		r, cfunc_rpcall, 3, 1, (void *)state, (void *)code,
		(void *)callback);
}

bool ruleset_update(
	struct ruleset *restrict r, const char *restrict modname,
	const char *restrict chunkname, struct stream *code)
{
	return ruleset_pcall(
		r, cfunc_update, 3, 0, (void *)modname, (void *)chunkname,
		(void *)code);
}

bool ruleset_loadfile(struct ruleset *restrict r, const char *restrict filename)
{
	struct stream *restrict const s = codec_lua_reader(filename);
	if (s == NULL) {
		return false;
	}
	const bool ok = ruleset_pcall(r, cfunc_loadfile, 1, 0, (void *)s);
	stream_close(s);
	return ok;
}

bool ruleset_loadconfig(
	struct ruleset *restrict r, const char *restrict filename)
{
	struct stream *restrict const s = codec_lua_reader(filename);
	if (s == NULL) {
		return false;
	}
	const bool ok = ruleset_pcall(r, cfunc_loadconfig, 1, 0, (void *)s);
	stream_close(s);
	return ok;
}

bool ruleset_isvalid(struct ruleset *restrict r)
{
	lua_State *restrict const L = r->L;
	const bool valid = (lua_getglobal(L, "ruleset") == LUA_TTABLE);
	lua_pop(L, 1);
	return valid;
}

bool ruleset_gc(struct ruleset *restrict r)
{
	return ruleset_pcall(r, cfunc_gc, 0, 0);
}

static bool dispatch_request(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict func, const char *restrict request,
	const char *restrict username, const char *restrict password,
	struct ruleset_callback *callback)
{
	const bool ok = ruleset_pcall(
		r, cfunc_request, 6, 1, (void *)state, (void *)func,
		(void *)request, (void *)username, (void *)password,
		(void *)callback);
	if (!ok) {
		LOGW_F("ruleset.%s: %s", func, ruleset_geterror(r, NULL));
		return false;
	}
	return true;
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	return dispatch_request(
		r, state, "resolve", request, username, password, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	return dispatch_request(
		r, state, "route", request, username, password, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
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
	struct ruleset *restrict r, const double dt, const char *restrict query,
	size_t *len)
{
	lua_State *restrict const L = r->L;
	const bool ok =
		ruleset_pcall(r, cfunc_stats, 2, 1, (void *)&dt, (void *)query);
	if (!ok) {
		LOGW_F("ruleset.stats: %s", ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_tolstring(L, -1, len);
}

const char *ruleset_metrics(struct ruleset *restrict r, size_t *len)
{
	lua_State *restrict const L = r->L;
	const bool ok = ruleset_pcall(r, cfunc_metrics, 0, 1);
	if (!ok) {
		LOGW_F("ruleset.metrics: %s", ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_tolstring(L, -1, len);
}

const char *ruleset_healthy(struct ruleset *restrict r, size_t *len)
{
	lua_State *restrict const L = r->L;
	const bool ok = ruleset_pcall(r, cfunc_healthy, 0, 1);
	if (!ok) {
		/* the health check itself failed: report it as unhealthy */
		const char *err = ruleset_geterror(r, len);
		LOGW_F("ruleset.healthy: %s", err);
		return err;
	}
	size_t n;
	const char *s = lua_tolstring(L, -1, &n);
	if (s == NULL || n == 0) {
		if (len != NULL) {
			*len = 0;
		}
		return NULL; /* undefined / nil / empty: healthy */
	}
	if (len != NULL) {
		*len = n;
	}
	return s; /* unhealthy: error message */
}

#endif /* WITH_RULESET */
