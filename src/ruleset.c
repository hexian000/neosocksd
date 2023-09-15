#include "ruleset.h"
#include "resolver.h"

#if WITH_RULESET

#include "utils/buffer.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "conf.h"
#include "dialer.h"
#include "http.h"
#include "sockutil.h"
#include "util.h"

#include "luaconf.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <ev.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <regex.h>

#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ruleset {
	struct ev_loop *loop;
	struct ruleset_memstats heap;
	lua_State *L;
	struct ev_timer w_ticker;
	struct ev_idle w_idle;
};

#define ASYNC_CALLBACK_TABLE "async"

static struct ruleset *find_ruleset(lua_State *L)
{
	void *ud;
	CHECK(lua_getallocf(L, &ud) != NULL);
	return ud;
}

static void find_callback(lua_State *restrict L, const int idx)
{
	assert(idx > 0);
	const char *func = lua_topointer(L, idx);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_replace(L, idx);
	lua_pop(L, 1);
}

static struct dialreq *pop_dialreq(lua_State *restrict L, const int n)
{
	if (n < 1) {
		return NULL;
	}
	const size_t nproxy = (size_t)(n - 1);
	struct dialreq *req = dialreq_new(nproxy);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	size_t len;
	for (size_t i = 0; i <= nproxy; i++) {
		const char *s = lua_tolstring(L, -1, &len);
		if (s == NULL) {
			dialreq_free(req);
			return NULL;
		}
		if (i < nproxy) {
			if (!dialreq_setproxy(req, i, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		} else {
			if (!dialaddr_set(&req->addr, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		}
		lua_pop(L, 1);
	}
	return req;
}

static int ruleset_traceback(lua_State *restrict L)
{
	/* DEBUG ONLY: unprotected allocation calls may panic if OOM */
	luaL_traceback(L, L, lua_tostring(L, -1), 1);
	return 1;
}

static void check_memlimit(const struct ruleset *restrict r)
{
	const size_t memlimit = G.conf->memlimit;
	if (memlimit == 0 || (r->heap.byt_allocated >> 20u) < memlimit) {
		return;
	}
	lua_gc(r->L, LUA_GCCOLLECT, 0);
}

static int ruleset_pcall(
	struct ruleset *restrict r, lua_CFunction func, int nargs, int nresults,
	...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
	const bool traceback = G.conf->traceback;
	if (traceback) {
		lua_pushcfunction(L, ruleset_traceback);
	}
	lua_pushcfunction(L, func);
	va_list args;
	va_start(args, nresults);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(args, void *));
	}
	va_end(args);
	return lua_pcall(L, nargs, nresults, traceback ? 1 : 0);
}

static int regex_gc_(lua_State *restrict L)
{
	regex_t *preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
}

/* regex.compile(pat) */
static int regex_compile_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *pat = lua_tostring(L, 1);
	regex_t *preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pat, REG_EXTENDED);
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_setmetatable(L, -2);
	return 1;
}

/* regex.find(reg, s) */
static int regex_find_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TUSERDATA);
	regex_t *preg = lua_touserdata(L, 1);
	luaL_checktype(L, 2, LUA_TSTRING);
	const char *s = lua_tostring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	} else if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushinteger(L, match.rm_so + 1);
	lua_pushinteger(L, match.rm_eo);
	return 2;
}

/* regex.match(reg, s) */
static int regex_match_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TUSERDATA);
	regex_t *preg = lua_touserdata(L, 1);
	luaL_checktype(L, 2, LUA_TSTRING);
	const char *s = lua_tostring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	} else if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushlstring(L, s + match.rm_so, match.rm_eo - match.rm_so);
	return 1;
}

static int luaopen_regex(lua_State *restrict L)
{
	lua_newtable(L);
	lua_pushcfunction(L, regex_find_);
	lua_setfield(L, -2, "find");
	lua_pushcfunction(L, regex_match_);
	lua_setfield(L, -2, "match");

	lua_newtable(L);
	lua_pushvalue(L, -2);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, regex_gc_);
	lua_setfield(L, -2, "__gc");
	/* capture the metatable as an upvalue */
	lua_pushcclosure(L, regex_compile_, 1);
	lua_setfield(L, -2, "compile");
	return 1;
}

/* invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke_(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	for (int i = 1; i <= MAX(2, n); i++) {
		luaL_checktype(L, i, LUA_TSTRING);
	}
	struct dialreq *req = pop_dialreq(L, n - 1);
	if (req == NULL) {
		return luaL_error(L, "invalid connect request");
	}
	struct ruleset *restrict r = find_ruleset(L);
	size_t len;
	const char *code = lua_tolstring(L, 1, &len);
	http_invoke(r->loop, req, code, len);
	return 0;
}

static int format_addr_(lua_State *restrict L)
{
	const struct sockaddr *sa = lua_topointer(L, -1);
	if (sa == NULL) {
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}
	const int af = sa->sa_family;
	switch (af) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in *)sa)->sin_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			return luaL_error(L, "%s", strerror(err));
		}
		lua_pop(L, 1);
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			return luaL_error(L, "%s", strerror(err));
		}
		lua_pop(L, 1);
		lua_pushstring(L, addr_str);
	} break;
	default:
		return luaL_error(L, "unknown af:%jd", af);
	}
	return 1;
}

static int api_resolve_cb_(lua_State *restrict L)
{
	lua_pushvalue(L, lua_upvalueindex(2)); /* cb */
	lua_pushvalue(L, lua_upvalueindex(1)); /* host */
	lua_pushvalue(L, 1); /* addr */
	lua_call(L, 2, 0);
	return 0;
}

static int resolve_cb_(lua_State *restrict L)
{
	struct resolve_query *q = (void *)lua_topointer(L, 1);
	format_addr_(L);
	luaL_getsubtable(L, LUA_REGISTRYINDEX, ASYNC_CALLBACK_TABLE);
	lua_rawgetp(L, -1, q);
	lua_pushnil(L); /* t, cb, nil */
	lua_rawsetp(L, -3, q);
	lua_pushvalue(L, 2);
	lua_call(L, 1, 0); /* api_resolve_cb_ */
	return 0;
}

static void resolve_cb(
	handle_t h, struct ev_loop *loop, void *ctx, const struct sockaddr *sa)
{
	UNUSED(loop);
	struct ruleset *restrict r = ctx;
	const int ret = ruleset_pcall(r, resolve_cb_, 2, 0, FROM_HANDLE(h), sa);
	if (ret != LUA_OK) {
		lua_State *restrict L = r->L;
		LOGE_F("resolve callback: %s", lua_tostring(L, -1));
		return;
	}
}

/* resolve(host, cb) */
static int api_resolve_async_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *name = luaL_checkstring(L, 1);
	luaL_checkany(L, 2);
	const handle_t h = resolve_do(
		G.resolver,
		(struct resolve_cb){
			.cb = resolve_cb,
			.ctx = find_ruleset(L),
		},
		name, NULL, G.conf->resolve_pf);
	if (h == INVALID_HANDLE) {
		return luaL_error(
			L, "resolve \"%s\" failed: out of memory", name);
	}
	luaL_getsubtable(L, LUA_REGISTRYINDEX, ASYNC_CALLBACK_TABLE);
	lua_pushvalue(L, 1); /* host */
	lua_pushvalue(L, 2); /* cb */
	lua_pushcclosure(L, api_resolve_cb_, 2);
	lua_rawsetp(L, -2, FROM_HANDLE(h));
	return 0;
}

/* resolve(host) */
static int api_resolve_(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	if (n > 1) {
		return api_resolve_async_(L);
	}
	const char *name = luaL_checkstring(L, 1);
	sockaddr_max_t addr;
	if (!resolve_addr(&addr, name, NULL, G.conf->resolve_pf)) {
		return luaL_error(L, "resolve failed");
	}
	lua_pushlightuserdata(L, &addr.sa);
	return format_addr_(L);
}

/* parse_ipv4(ipv4) */
static int api_parse_ipv4_(lua_State *restrict L)
{
	const char *s = lua_tostring(L, 1);
	if (s == NULL) {
		return 0;
	}
	struct in_addr in;
	if (inet_pton(AF_INET, s, &in) != 1) {
		return 0;
	}
	const uint32_t *addr = (void *)&in;
	lua_pushinteger(L, read_uint32((const void *)&addr[0]));
	return 1;
}

/* parse_ipv6(ipv6) */
static int api_parse_ipv6_(lua_State *restrict L)
{
	const char *s = lua_tostring(L, 1);
	if (s == NULL) {
		return 0;
	}
	struct in6_addr in6;
	if (inet_pton(AF_INET6, s, &in6) != 1) {
		return 0;
	}
	const lua_Unsigned *addr = (void *)&in6;
#if LUA_MAXUNSIGNED >= UINT64_MAX
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[0]));
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[1]));
	return 2;
#else
	lua_pushinteger(L, read_uint32((const void *)&addr[0]));
	lua_pushinteger(L, read_uint32((const void *)&addr[1]));
	lua_pushinteger(L, read_uint32((const void *)&addr[2]));
	lua_pushinteger(L, read_uint32((const void *)&addr[3]));
	return 4;
#endif
}

static int ruleset_tick_(lua_State *restrict L)
{
	find_callback(L, 1);
	lua_pushnumber(L, *(ev_tstamp *)lua_topointer(L, 2));
	lua_replace(L, 2);
	lua_call(L, 1, 0);
	return 0;
}

static void tick_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(revents);
	struct ruleset *restrict r = watcher->data;
	const char *func = "tick";
	ev_tstamp now = ev_now(loop);
	const int ret = ruleset_pcall(r, ruleset_tick_, 2, 0, func, &now);
	if (ret != LUA_OK) {
		lua_State *restrict L = r->L;
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		return;
	}
}

/* setinterval(interval) */
static int api_setinterval_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	double interval = lua_tonumber(L, 1);

	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w_ticker = &r->w_ticker;
	ev_timer_stop(r->loop, w_ticker);
	if (!isnormal(interval)) {
		return 0;
	}

	interval = CLAMP(interval, 1e-3, 1e+9);
	ev_timer_set(w_ticker, interval, interval);
	w_ticker->data = r;
	ev_timer_start(r->loop, w_ticker);
	return 0;
}

static int ruleset_idle_(lua_State *restrict L)
{
	find_callback(L, 1);
	lua_call(L, 0, 0);
	return 0;
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	UNUSED(revents);
	ev_idle_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	const char *func = "idle";
	const int ret = ruleset_pcall(r, ruleset_idle_, 1, 0, func);
	if (ret != LUA_OK) {
		LOGE_F("ruleset.%s: %s", func, lua_tostring(r->L, -1));
		return;
	}
}

/* setidle() */
static int api_setidle_(lua_State *restrict L)
{
	struct ruleset *restrict r = find_ruleset(L);
	ev_idle_start(r->loop, &r->w_idle);
	return 0;
}

static int luaopen_neosocksd(lua_State *restrict L)
{
	const luaL_Reg apilib[] = {
		{ "invoke", api_invoke_ },
		{ "resolve", api_resolve_ },
		{ "setinterval", api_setinterval_ },
		{ "setidle", api_setidle_ },
		{ "parse_ipv4", api_parse_ipv4_ },
		{ "parse_ipv6", api_parse_ipv6_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, apilib);
	return 1;
}

static int ruleset_luainit_(lua_State *restrict L)
{
	/* load all libraries */
	luaL_openlibs(L);
	luaL_requiref(L, "neosocksd", luaopen_neosocksd, 1);
	luaL_requiref(L, "regex", luaopen_regex, 1);
	lua_pop(L, 2);
	lua_pushboolean(L, !LOGLEVEL(LOG_LEVEL_DEBUG));
	lua_setglobal(L, "NDEBUG");
	/* prefer generational GC on supported lua versions */
#ifdef LUA_GCGEN
	lua_gc(L, LUA_GCGEN, 0, 0);
#endif
	return 0;
}

static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct ruleset *restrict r = ud;
	if (nsize == 0) {
		/* free */
		free(ptr);
		if (ptr != NULL) {
			r->heap.byt_allocated -= osize;
			r->heap.num_object--;
		}
		return NULL;
	}
	if (ptr == NULL) {
		/* malloc */
		void *ret = malloc(nsize);
		if (ret != NULL) {
			r->heap.num_object++;
			r->heap.byt_allocated += nsize;
		}
		return ret;
	}
	/* realloc */
	void *ret = realloc(ptr, nsize);
	if (ret != NULL) {
		r->heap.byt_allocated = r->heap.byt_allocated - osize + nsize;
	}
	return ret;
}

static int l_panic(lua_State *L)
{
	const char *msg = lua_tostring(L, -1);
	if (msg == NULL) {
		msg = "(error object is not a string)";
	}
	LOGF_F("panic: %s", msg);
	return 0; /* return to Lua to abort */
}

struct ruleset *ruleset_new(struct ev_loop *loop)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	r->loop = loop;
	r->heap = (struct ruleset_memstats){ 0 };
	lua_State *restrict L = lua_newstate(l_alloc, r);
	if (L == NULL) {
		ruleset_free(r);
		return NULL;
	}
	(void)lua_atpanic(L, l_panic);
	r->L = L;
	{
		/* initialize in advance to prevent undefined behavior */
		struct ev_timer *restrict w_ticker = &r->w_ticker;
		ev_timer_init(w_ticker, tick_cb, 1.0, 1.0);
		w_ticker->data = r;
		struct ev_idle *restrict w_idle = &r->w_idle;
		ev_idle_init(w_idle, idle_cb);
		ev_set_priority(w_idle, EV_MINPRI);
		w_idle->data = r;
	}

	switch (ruleset_pcall(r, ruleset_luainit_, 0, 0)) {
	case LUA_OK:
		break;
	case LUA_ERRMEM:
		ruleset_free(r);
		return NULL;
	default:
		FAIL();
	}
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

static int ruleset_invoke_(lua_State *restrict L)
{
	const char *code = lua_topointer(L, 1);
	const size_t len = *(size_t *)lua_topointer(L, 2);
	lua_settop(L, 0);
	if (luaL_loadbuffer(L, code, len, "=rpc") != LUA_OK) {
		return luaL_error(
			L, "error loading rpc:\n\t%s", lua_tostring(L, -1));
	}
	lua_call(L, 0, 0);
	return 0;
}

/* always reload and replace existing module */
static int ruleset_require_(lua_State *restrict L)
{
	const int idx_modname = 1;
	luaL_checktype(L, idx_modname, LUA_TSTRING);
	const int idx_openf = 2;
	luaL_checktype(L, idx_openf, LUA_TFUNCTION);
	lua_settop(L, 2);
	const int idx_loaded = 3;
	luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
	const int idx_glb = 4;
	lua_geti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);

	int glb = 0;
	/* LOADED[modname] */
	lua_pushvalue(L, idx_modname);
	if (lua_gettable(L, idx_loaded) != LUA_TNIL) {
		lua_pushvalue(L, idx_modname);
		lua_gettable(L, idx_glb); /* _G[modname] */
		glb = lua_compare(L, -2, -1, LUA_OPEQ);
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

static int ruleset_update_(lua_State *restrict L)
{
	const char *modname = lua_topointer(L, 1);
	const char *code = lua_topointer(L, 2);
	const size_t len = *(size_t *)lua_topointer(L, 3);
	lua_pop(L, 3);
	if (modname == NULL) {
		if (luaL_loadbuffer(L, code, len, "=ruleset") != LUA_OK) {
			return luaL_error(
				L, "error loading ruleset:\n\t%s",
				lua_tostring(L, -1));
		}
		lua_pushstring(L, "ruleset");
		lua_call(L, 1, 1);
		if (!lua_istable(L, -1)) {
			lua_pushstring(L, "ruleset does not return a table");
			return lua_error(L);
		}
		lua_setglobal(L, "ruleset");
		return 0;
	}
	lua_pushcfunction(L, ruleset_require_);
	lua_pushstring(L, modname);
	{
		const size_t namelen = strlen(modname);
		char name[1 + namelen + 1];
		name[0] = '=';
		memcpy(name + 1, modname, namelen);
		name[1 + namelen] = '\0';
		if (luaL_loadbuffer(L, code, len, name) != LUA_OK) {
			return luaL_error(
				L, "error loading module '%s':\n\t%s", modname,
				lua_tostring(L, -1));
		}
	}
	lua_call(L, 2, 0);
	return 0;
}

static int ruleset_loadfile_(lua_State *restrict L)
{
	const char *filename = lua_topointer(L, 1);
	lua_pop(L, 1);
	if (luaL_loadfile(L, filename) != LUA_OK) {
		return luaL_error(
			L, "error loading file '%s':\n\t%s", filename,
			lua_tostring(L, -1));
	}
	lua_pushstring(L, "ruleset");
	lua_call(L, 1, 1);
	if (!lua_istable(L, -1)) {
		lua_pushstring(L, "ruleset does not return a table");
		return lua_error(L);
	}
	lua_setglobal(L, "ruleset");
	return 0;
}

const char *
ruleset_invoke(struct ruleset *r, const char *code, const size_t len)
{
	lua_State *restrict L = r->L;
	const int ret = ruleset_pcall(
		r, ruleset_invoke_, 2, 0, (void *)code, (void *)&len);
	if (ret != LUA_OK) {
		const char *err = lua_tostring(L, -1);
		LOGE_F("ruleset invoke: %s", err);
		return err;
	}
	return NULL;
}

const char *ruleset_update(
	struct ruleset *r, const char *modname, const char *code,
	const size_t len)
{
	lua_State *restrict L = r->L;
	const int ret =
		ruleset_pcall(r, ruleset_update_, 3, 0, modname, code, &len);
	if (ret != LUA_OK) {
		const char *err = lua_tostring(L, -1);
		LOGE_F("ruleset update: %s", err);
		return err;
	}
	return NULL;
}

const char *ruleset_loadfile(struct ruleset *r, const char *filename)
{
	lua_State *restrict L = r->L;
	const int ret = ruleset_pcall(r, ruleset_loadfile_, 1, 0, filename);
	if (ret != LUA_OK) {
		const char *err = lua_tostring(L, -1);
		LOGE_F("ruleset loadfile: %s", err);
		return err;
	}
	return NULL;
}

void ruleset_gc(struct ruleset *restrict r)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
}

static int ruleset_request_(lua_State *restrict L)
{
	find_callback(L, 1);
	const char *request = lua_topointer(L, 2);
	(void)lua_pushstring(L, request);
	lua_replace(L, 2);

	lua_call(L, 1, LUA_MULTRET);
	const int n = lua_gettop(L);
	if (n < 1) {
		return 0;
	}
	const int type = lua_type(L, -1);
	switch (type) {
	case LUA_TSTRING:
		break;
	case LUA_TNIL:
		return 0;
	default:
		LOGE_F("request \"%s\": invalid return type %s", request,
		       lua_typename(L, type));
		return 0;
	}
	struct dialreq *req = pop_dialreq(L, n);
	if (req == NULL) {
		LOGE_F("request \"%s\": invalid return", request);
	}
	lua_pushlightuserdata(L, req);
	return 1;
}

static struct dialreq *
dispatch_req(struct ruleset *restrict r, const char *func, const char *request)
{
	lua_State *restrict L = r->L;
	const int ret = ruleset_pcall(
		r, ruleset_request_, 2, 1, (void *)func, (void *)request);
	if (ret != LUA_OK) {
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		return NULL;
	}
	return (struct dialreq *)lua_topointer(L, -1);
}

struct dialreq *ruleset_resolve(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "resolve", request);
}

struct dialreq *ruleset_route(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "route", request);
}

struct dialreq *ruleset_route6(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "route6", request);
}

void ruleset_memstats(
	const struct ruleset *restrict r, struct ruleset_memstats *restrict s)
{
	*s = r->heap;
}

static int ruleset_stats_(lua_State *restrict L)
{
	find_callback(L, 1);
	lua_pushnumber(L, *(double *)lua_topointer(L, -1));
	lua_replace(L, 2);
	lua_call(L, 1, 1);
	return 1;
}

const char *ruleset_stats(struct ruleset *restrict r, const double dt)
{
	lua_State *restrict L = r->L;
	const char *func = "stats";
	const int ret = ruleset_pcall(
		r, ruleset_stats_, 2, 1, (void *)func, (void *)&dt);
	if (ret != LUA_OK) {
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		return NULL;
	}
	if (!lua_isstring(L, -1)) {
		return NULL;
	}
	return lua_tostring(L, -1);
}

#endif /* WITH_RULESET */
