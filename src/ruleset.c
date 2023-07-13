#include "ruleset.h"
#include "utils/buffer.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "utils/check.h"
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

#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ruleset {
	const struct config *conf;
	lua_State *L;
	struct ev_loop *loop;
	struct ev_timer ticker;
};

static struct ruleset *find_ruleset(lua_State *restrict L)
{
	if (lua_getfield(L, LUA_REGISTRYINDEX, "ruleset") !=
	    LUA_TLIGHTUSERDATA) {
		luaL_error(L, "lua registry is corrupted");
	}
	struct ruleset *r = (struct ruleset *)lua_topointer(L, -1);
	lua_pop(L, 1);
	return r;
}

static int find_callback(lua_State *restrict L, int idx)
{
	const char *func = lua_topointer(L, idx);
	if (lua_getglobal(L, "ruleset") != LUA_TTABLE) {
		lua_pop(L, 1);
		return 0;
	}
	if (lua_getfield(L, -1, func) != LUA_TFUNCTION) {
		lua_pop(L, 2);
		return 0;
	}
	lua_remove(L, -2);
	return 1;
}

static struct dialreq *pop_dialreq(lua_State *restrict L, int n)
{
	if (n < 1) {
		return NULL;
	}
	size_t len;
	const char *direct = lua_tolstring(L, -n, &len);
	if (direct == NULL) {
		LOGE_F("ruleset: returned address #%d is not a string", 1);
		return NULL;
	}
	struct dialaddr addr;
	if (!dialaddr_set(&addr, direct, len)) {
		LOGE_F("ruleset: returned address #%d is not valid", 1);
		return NULL;
	}
	struct dialreq *req = dialreq_new(&addr, (size_t)n);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	for (int i = 1; i < n; i++) {
		const char *s = lua_tolstring(L, -i, &len);
		if (s == NULL) {
			LOGE_F("ruleset: returned address #%d is not a string",
			       n - i);
			dialreq_free(req);
			return NULL;
		}
		if (!dialreq_proxy(req, s, len)) {
			LOGE_F("ruleset: returned address #%d is not valid",
			       n - i);
			dialreq_free(req);
			return NULL;
		}
	}
	lua_pop(L, n);
	return req;
}

static int ruleset_traceback(lua_State *restrict L)
{
	/* DEBUG ONLY: unprotected allocation calls may panic if OOM */
	luaL_traceback(L, L, lua_tostring(L, -1), 1);
	return 1;
}

static int ruleset_pcall(
	struct ruleset *restrict r, lua_CFunction func, int nargs, int nresults,
	...)
{
	const bool traceback = r->conf->traceback;
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
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

/* invoke(code, addr, proxyN, ..., proxy1) */
static int invoke_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	luaL_checktype(L, 2, LUA_TSTRING);
	const int n = lua_gettop(L);
	for (int i = 2; i < n; i++) {
		luaL_checktype(L, i + 1, LUA_TSTRING);
	}
	struct dialreq *req = pop_dialreq(L, n - 1);
	if (req == NULL) {
		luaL_error(L, "invoke failed");
	}
	struct ruleset *restrict r = find_ruleset(L);
	size_t len;
	const char *code = lua_tolstring(L, 1, &len);
	(void)http_invoke(r->loop, r->conf, req, code, len);
	return 0;
}

/* resolve(host) */
static int resolve_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *s = lua_tostring(L, 1);
	struct ruleset *restrict r = find_ruleset(L);
	sockaddr_max_t addr;
	if (!resolve_hostname(&addr, s, r->conf->resolve_pf)) {
		const int err = errno;
		luaL_error(L, "%s", strerror(err));
	}
	const int af = addr.sa.sa_family;
	switch (af) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		const char *addr_str =
			inet_ntop(af, &addr.in.sin_addr, buf, sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			luaL_error(L, "%s", strerror(err));
		}
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str =
			inet_ntop(af, &addr.in6.sin6_addr, buf, sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			luaL_error(L, "%s", strerror(err));
		}
		lua_pushstring(L, addr_str);
	} break;
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

/* parse_ipv4(ipv4) */
static int parse_ipv4_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *s = lua_tostring(L, 1);
	struct in_addr in;
	if (inet_pton(AF_INET, s, &in) != 1) {
		return 0;
	}
	const uint32_t *addr = (void *)&in;
	lua_pushinteger(L, read_uint32((const void *)&addr[0]));
	return 1;
}

/* parse_ipv6(ipv6) */
static int parse_ipv6_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *s = lua_tostring(L, 1);
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
	if (find_callback(L, 1) != 1) {
		return 0;
	}
	lua_replace(L, 1);
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
static int setinterval_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	double interval = lua_tonumber(L, 1);

	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w_timer = &r->ticker;
	ev_timer_stop(r->loop, w_timer);
	if (!isnormal(interval)) {
		return 0;
	}

	interval = CLAMP(interval, 1e-3, 1e+9);
	ev_timer_set(w_timer, interval, interval);
	w_timer->data = r;
	ev_timer_start(r->loop, w_timer);
	return 0;
}

static int luaopen_neosocksd(lua_State *restrict L)
{
	lua_newtable(L);
	lua_pushcfunction(L, invoke_);
	lua_setfield(L, -2, "invoke");
	lua_pushcfunction(L, resolve_);
	lua_setfield(L, -2, "resolve");
	lua_pushcfunction(L, parse_ipv4_);
	lua_setfield(L, -2, "parse_ipv4");
	lua_pushcfunction(L, parse_ipv6_);
	lua_setfield(L, -2, "parse_ipv6");
	lua_pushcfunction(L, setinterval_);
	lua_setfield(L, -2, "setinterval");
	return 1;
}

static int ruleset_luainit_(lua_State *restrict L)
{
	assert(lua_gettop(L) == 1);
	lua_setfield(L, LUA_REGISTRYINDEX, "ruleset");
	/* load all standard libraries */
	luaL_openlibs(L);
	luaL_requiref(L, "neosocksd", luaopen_neosocksd, 1);
	lua_pop(L, 1);
	lua_pushboolean(L, !LOGLEVEL(LOG_LEVEL_DEBUG));
	lua_setglobal(L, "NDEBUG");
	/* prefer generational GC on supported lua versions */
#ifdef LUA_GCGEN
	lua_gc(L, LUA_GCGEN, 0, 0);
#endif
	return 0;
}

struct ruleset *ruleset_new(struct ev_loop *loop, const struct config *conf)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		ruleset_free(r);
		return NULL;
	}
	r->conf = conf;
	r->L = L;
	r->loop = loop;
	{
		/* initialize in advance to prevent undefined behavior */
		struct ev_timer *restrict w_timer = &r->ticker;
		ev_timer_init(w_timer, tick_cb, 1.0, 1.0);
		w_timer->data = r;
	}

	void *ptr = (void *)r;
	switch (ruleset_pcall(r, ruleset_luainit_, 1, 0, ptr)) {
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
	struct ev_timer *restrict w_timer = &r->ticker;
	ev_timer_stop(r->loop, w_timer);
	lua_close(r->L);
	free(r);
}

static int ruleset_invoke_(lua_State *restrict L)
{
	const char *code = lua_topointer(L, 1);
	const size_t len = *(size_t *)lua_topointer(L, 2);
	lua_pop(L, 2);
	if (luaL_loadbuffer(L, code, len, "=rpc") != LUA_OK) {
		lua_error(L);
	}
	lua_call(L, 0, 0);
	lua_pushboolean(L, 1);
	return 1;
}

static int ruleset_load_(lua_State *restrict L)
{
	const char *code = lua_topointer(L, 1);
	const size_t len = *(size_t *)lua_topointer(L, 2);
	lua_pop(L, 2);
	if (luaL_loadbuffer(L, code, len, "=ruleset") != LUA_OK) {
		lua_error(L);
	}
	lua_call(L, 0, 1);
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, 0);
		return 1;
	}
	lua_setglobal(L, "ruleset");
	lua_pushboolean(L, 1);
	return 1;
}

static int ruleset_loadfile_(lua_State *restrict L)
{
	const char *filename = lua_topointer(L, 1);
	lua_pop(L, 2);
	if (luaL_loadfile(L, filename) != LUA_OK) {
		lua_error(L);
	}
	lua_call(L, 0, 1);
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, 0);
		return 1;
	}
	lua_setglobal(L, "ruleset");
	lua_pushboolean(L, 1);
	return 1;
}

static const char *dispatch_exec(
	struct ruleset *restrict r, lua_CFunction func, const char *method,
	const char *code, const size_t len)
{
	lua_State *restrict L = r->L;
	const int ret =
		ruleset_pcall(r, func, 2, 1, (void *)code, (void *)&len);
	if (ret != LUA_OK) {
		const char *err = lua_tostring(L, -1);
		LOGE_F("ruleset %s: %s", method, err);
		return err;
	}
	return NULL;
}

const char *
ruleset_invoke(struct ruleset *r, const char *code, const size_t len)
{
	LOGD_F("ruleset invoke: %zu bytes", len);
	return dispatch_exec(r, ruleset_invoke_, "invoke", code, len);
}

const char *ruleset_load(struct ruleset *r, const char *code, const size_t len)
{
	LOGD_F("ruleset load: %zu bytes", len);
	return dispatch_exec(r, ruleset_load_, "load", code, len);
}

const char *ruleset_loadfile(struct ruleset *r, const char *filename)
{
	return dispatch_exec(r, ruleset_loadfile_, "loadfile", filename, 0);
}

void ruleset_gc(struct ruleset *restrict r)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
}

static struct dialreq *request_accept(const char *domain)
{
	struct dialaddr addr;
	if (!dialaddr_set(&addr, domain, strlen(domain))) {
		return NULL;
	}
	struct dialreq *req = dialreq_new(&addr, 0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	return req;
}

static int ruleset_request_(lua_State *restrict L)
{
	const char *func = lua_topointer(L, 1);
	const char *request = lua_topointer(L, 2);
	if (find_callback(L, 1) != 1) {
		struct dialreq *req = request_accept(request);
		lua_pushlightuserdata(L, req);
		return 1;
	}
	lua_replace(L, 1);
	(void)lua_pushstring(L, request);
	lua_replace(L, 2);
	lua_call(L, 1, LUA_MULTRET);
	const int n = lua_gettop(L);
	if (n < 1) {
		return 0;
	}
	switch (lua_type(L, -1)) {
	case LUA_TSTRING:
		break;
	case LUA_TNIL:
		return 0;
	default:
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		return 0;
	}
	struct dialreq *req = pop_dialreq(L, n);
	if (req == NULL) {
		LOGE("Lua script returned an invalid address");
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

size_t ruleset_memused(struct ruleset *restrict r)
{
	lua_State *restrict L = r->L;
	return ((size_t)lua_gc(L, LUA_GCCOUNT, 0) << 10u) |
	       (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
}

static int ruleset_stats_(lua_State *restrict L)
{
	if (find_callback(L, 1) != 1) {
		return 0;
	}
	lua_replace(L, 1);
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
