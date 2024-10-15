/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset.h"

#if WITH_RULESET

#include "api_client.h"
#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include "ruleset/await.h"
#include "ruleset/base.h"
#include "ruleset/marshal.h"
#include "ruleset/regex.h"
#include "ruleset/zlib.h"

#include "net/addr.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MT_RPCALL "rpcall"

/* request(func, request, username, password) */
static int cfunc_request_(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 4);
	const char *func = lua_touserdata(L, 1);
	const char *request = lua_touserdata(L, 2);
	const char *username = lua_touserdata(L, 3);
	const char *password = lua_touserdata(L, 4);
	lua_settop(L, 0);

	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_pushstring(L, request);
	lua_pushstring(L, username);
	lua_pushstring(L, password);
	lua_call(L, 3, LUA_MULTRET);
	const int n = lua_gettop(L) - 1;
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
		LOGE_F("request `%s': invalid return type %s", request,
		       lua_typename(L, type));
		return 0;
	}
	struct dialreq *req = make_dialreq_(L, n);
	if (req == NULL) {
		LOGE_F("request `%s': invalid return", request);
	}
	lua_pushlightuserdata(L, req);
	return 1;
}

/* loadfile(filename) */
static int cfunc_loadfile_(lua_State *restrict L)
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
static int cfunc_invoke_(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 1);
	void *stream = lua_touserdata(L, 1);
	lua_settop(L, 0);

	if (lua_load(L, ruleset_reader, stream, "=(invoke)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_newtable(L);
	lua_pushvalue(L, LUA_REGISTRYINDEX);
	/* lua stack: chunk t mt _G */
	lua_setfield(L, -2, "__index");
	(void)lua_setmetatable(L, -2);
	if (lua_setupvalue(L, -2, -1) == NULL) {
		lua_pop(L, 1);
	}
	lua_call(L, 0, 0);
	return 0;
}

struct rpcall_state {
	rpcall_return_fn callback;
	void *data;
};

static int rpcall_gc_(lua_State *restrict L)
{
	struct rpcall_state *restrict state = lua_touserdata(L, 1);
	if (state->callback != NULL) {
		state->callback(state->data, NULL, 0);
		state->callback = NULL;
	}
	return 0;
}

static int rpcall_return_(lua_State *restrict co)
{
	struct rpcall_state *restrict state =
		lua_touserdata(co, lua_upvalueindex(1));
	if (state->callback == NULL) {
		return 0;
	}
	size_t len;
	const char *s = luaL_checklstring(co, 1, &len);
	state->callback(state->data, s, len);
	state->callback = NULL;
	return 0;
}

/* rpcall(codestream, callback, data) */
static int cfunc_rpcall_(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 3);
	void *stream = lua_touserdata(L, 1);
	struct rpcall_state *restrict ctx =
		lua_newuserdata(L, sizeof(struct rpcall_state));
	*(void **)&ctx->callback = lua_touserdata(L, 2);
	ctx->data = lua_touserdata(L, 3);
	if (luaL_newmetatable(L, MT_RPCALL)) {
		lua_pushcfunction(L, rpcall_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	lua_replace(L, 1);
	lua_settop(L, 1);
	if (lua_load(L, ruleset_reader, stream, "=(rpc)", "t")) {
		return lua_error(L);
	}
	lua_newtable(L);
	lua_pushvalue(L, 1);
	lua_pushcclosure(L, rpcall_return_, 1);
	lua_setfield(L, -2, "rpcall_return");
	lua_newtable(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
	/* lua stack: state chunk env mt _G */
	lua_setfield(L, -2, "__index");
	(void)lua_setmetatable(L, -2);
	if (lua_setupvalue(L, -2, 1) == NULL) {
		return 0;
	}
	lua_call(L, 0, 0);
	ASSERT(lua_gettop(L) == 1);
	return 1;
}

/* replace(modname, chunk) */
static int package_replace_(lua_State *restrict L)
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
static int cfunc_update_(lua_State *restrict L)
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
		char chunkname[1 + namelen + 1];
		chunkname[0] = '=';
		memcpy(chunkname + 1, name, namelen);
		chunkname[1 + namelen] = '\0';
		if (lua_load(L, ruleset_reader, stream, chunkname, NULL)) {
			return lua_error(L);
		}
	} else {
		if (lua_load(L, ruleset_reader, stream, chunkname, NULL)) {
			return lua_error(L);
		}
	}
	if (modname == NULL) {
		lua_pushliteral(L, "ruleset");
		lua_call(L, 1, 1);
		lua_setglobal(L, "ruleset");
		return 0;
	}
	(void)package_replace_(L);
	return 0;
}

/* stats(func, dt) */
static int cfunc_stats_(lua_State *restrict L)
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

/* tick(func, now) */
static int cfunc_tick_(lua_State *restrict L)
{
	ASSERT(lua_gettop(L) == 2);
	const char *func = lua_touserdata(L, 1);
	const ev_tstamp now = *(ev_tstamp *)lua_touserdata(L, 2);
	lua_settop(L, 0);

	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_replace(L, -2);
	lua_pushnumber(L, now);
	lua_call(L, 1, 0);
	return 0;
}

/* neosocksd.invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke_(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	for (int i = 1; i <= MAX(2, n); i++) {
		luaL_checktype(L, i, LUA_TSTRING);
	}
	struct dialreq *req = make_dialreq_(L, n - 1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ROUTE);
		return lua_error(L);
	}
	struct ruleset *restrict r = find_ruleset(L);
	size_t len;
	const char *code = lua_tolstring(L, 1, &len);
	struct api_client_cb cb = { NULL, NULL };
	api_invoke(r->loop, req, "/ruleset/invoke", code, len, cb);
	return 0;
}

/* neosocksd.resolve(host) */
static int api_resolve_(lua_State *restrict L)
{
	const char *name = luaL_checkstring(L, 1);
	union sockaddr_max addr;
	if (!resolve_addr(&addr, name, NULL, G.conf->resolve_pf)) {
		return 0;
	}
	lua_pushlightuserdata(L, &addr.sa);
	return format_addr_(L);
}

/* neosocksd.parse_ipv4(ipv4) */
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
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[0]));
	return 1;
}

/* neosocksd.parse_ipv6(ipv6) */
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
	const lua_Integer *addr = (void *)&in6;
#if LUA_32BITS
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[0]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[1]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[2]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[3]));
	return 4;
#else
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[0]));
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[1]));
	return 2;
#endif
}

static void tick_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct ruleset *restrict r = watcher->data;
	const char *func = "tick";
	const ev_tstamp now = ev_now(loop);
	const bool ok = ruleset_pcall(r, FUNC_TICK, 2, 0, func, &now);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_geterror(r, NULL));
		return;
	}
}

/* neosocksd.setinterval(interval) */
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

/* neosocksd.splithostport() */
static int api_splithostport_(lua_State *restrict L)
{
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + 1 + 5) {
		(void)lua_pushfstring(L, "address too long: %zu bytes", len);
		return lua_error(L);
	}
	char buf[len + 1];
	memcpy(buf, s, len);
	buf[len] = '\0';
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		return luaL_error(L, "invalid address: `%s'", s);
	}
	lua_pushstring(L, host);
	lua_pushstring(L, port);
	return 2;
}

/* neosocksd.config() */
static int api_config_(lua_State *restrict L)
{
	const struct config *restrict conf = G.conf;
	lua_createtable(L, 0, 8);
	lua_pushinteger(L, (lua_Integer)conf->log_level);
	lua_setfield(L, -2, "loglevel");
	lua_pushnumber(L, (lua_Number)conf->timeout);
	lua_setfield(L, -2, "timeout");
	lua_pushboolean(L, conf->auth_required);
	lua_setfield(L, -2, "auth_required");
	lua_pushboolean(L, conf->traceback);
	lua_setfield(L, -2, "traceback");
	lua_pushstring(L, conf->listen);
	lua_setfield(L, -2, "listen");
	lua_pushstring(L, conf->restapi);
	lua_setfield(L, -2, "api");
	lua_pushstring(L, conf->proxy);
	lua_setfield(L, -2, "proxy");
	lua_pushstring(L, conf->forward);
	lua_setfield(L, -2, "forward");
	return 1;
}

/* neosocksd.stats() */
static int api_stats_(lua_State *restrict L)
{
	struct server *restrict s = G.server;
	if (s == NULL) {
		return 0;
	}
	struct ruleset *restrict r = find_ruleset(L);
	const struct server_stats *restrict stats = &s->stats;
	lua_createtable(L, 0, 6);
	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	lua_setfield(L, -2, "lasterror");
	lua_pushinteger(L, (lua_Integer)stats->num_halfopen);
	lua_setfield(L, -2, "num_halfopen");
	lua_pushinteger(L, (lua_Integer)stats->num_sessions);
	lua_setfield(L, -2, "num_sessions");
	lua_pushinteger(L, (lua_Integer)stats->byt_up);
	lua_setfield(L, -2, "byt_up");
	lua_pushinteger(L, (lua_Integer)stats->byt_down);
	lua_setfield(L, -2, "byt_down");
	lua_pushnumber(L, (lua_Number)(ev_now(r->loop) - stats->started));
	lua_setfield(L, -2, "uptime");
	return 1;
}

/* neosocksd.now() */
static int api_now_(lua_State *restrict L)
{
	struct ruleset *restrict r = find_ruleset(L);
	const ev_tstamp now = ev_now(r->loop);
	lua_pushnumber(L, (lua_Number)now);
	return 1;
}

static int luaopen_neosocksd(lua_State *restrict L)
{
	lua_register(L, "marshal", api_marshal_);
	const luaL_Reg apilib[] = {
		{ "config", api_config_ },
		{ "invoke", api_invoke_ },
		{ "now", api_now_ },
		{ "parse_ipv4", api_parse_ipv4_ },
		{ "parse_ipv6", api_parse_ipv6_ },
		{ "resolve", api_resolve_ },
		{ "setinterval", api_setinterval_ },
		{ "splithostport", api_splithostport_ },
		{ "stats", api_stats_ },
		{ "traceback", ruleset_traceback_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, apilib);
	return 1;
}

static void init_registry(lua_State *restrict L)
{
	const char *strings[] = {
		ERR_MEMORY,
		ERR_BAD_REGISTRY,
		ERR_INVALID_ROUTE,
		ERR_NOT_YIELDABLE,
	};
	const int nstrings = (int)ARRAY_SIZE(strings);
	lua_createtable(L, nstrings, 0);
	for (int i = 0; i < nstrings; i++) {
		lua_pushstring(L, strings[i]);
		lua_rawseti(L, -2, i + 1);
	}
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_CONSTANT);

	const lua_CFunction funcs[] = {
		[FUNC_REQUEST] = cfunc_request_,
		[FUNC_LOADFILE] = cfunc_loadfile_,
		[FUNC_INVOKE] = cfunc_invoke_,
		[FUNC_UPDATE] = cfunc_update_,
		[FUNC_STATS] = cfunc_stats_,
		[FUNC_TICK] = cfunc_tick_,
		[FUNC_TRACEBACK] = ruleset_traceback_,
		[FUNC_RPCALL] = cfunc_rpcall_,
	};
	const int nfuncs = (int)ARRAY_SIZE(funcs) - 1;
	lua_createtable(L, nfuncs, 0);
	for (int i = 1; i <= nfuncs; i++) {
		lua_pushcfunction(L, funcs[i]);
		lua_seti(L, -2, i);
	}
	lua_seti(L, LUA_REGISTRYINDEX, RIDX_CFUNCTION);
}

static int ruleset_luainit_(lua_State *restrict L)
{
	init_registry(L);
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
		{ "neosocksd", luaopen_neosocksd },
		{ "await", luaopen_await },
		{ "regex", luaopen_regex },
		{ "zlib", luaopen_zlib },
		{ NULL, NULL },
	};
	for (const luaL_Reg *lib = libs; lib->func; lib++) {
		luaL_requiref(L, lib->name, lib->func, 1);
		lua_pop(L, 1);
	}
	/* set flags */
	lua_pushboolean(L, !LOGLEVEL(DEBUG));
	lua_setglobal(L, "NDEBUG");
	lua_pushboolean(L, G.conf->traceback);
	lua_setglobal(L, "traceback");
	return 0;
}

static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct ruleset *restrict r = ud;
	if (nsize == 0) {
		/* free */
		if (ptr != NULL) {
			free(ptr);
			r->vmstats.byt_allocated -= osize;
			r->vmstats.num_object--;
		}
		return NULL;
	}
	if (ptr == NULL) {
		/* malloc */
		void *ret = malloc(nsize);
		if (ret != NULL) {
			r->vmstats.num_object++;
			r->vmstats.byt_allocated += nsize;
		}
		return ret;
	}
	/* realloc */
	void *ret = realloc(ptr, nsize);
	if (ret != NULL) {
		r->vmstats.byt_allocated =
			r->vmstats.byt_allocated - osize + nsize;
	}
	return ret;
}

static int l_panic(lua_State *L)
{
	if (lua_isstring(L, -1)) {
		LOGF_F("panic: %s", lua_tostring(L, -1));
	} else {
		LOGF_F("panic: (%s: %p)", lua_typename(L, lua_type(L, -1)),
		       lua_topointer(L, -1));
	}
	LOG_STACK(FATAL, 0, "stacktrace");
	return 0; /* return to Lua to abort */
}

struct ruleset *ruleset_new(struct ev_loop *loop)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	r->loop = loop;
	r->vmstats = (struct ruleset_vmstats){ 0 };
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
	}

	lua_pushcfunction(L, ruleset_luainit_);
	switch (lua_pcall(L, 0, 0, 0)) {
	case LUA_OK:
		break;
	case LUA_ERRMEM:
		ruleset_free(r);
		return NULL;
	default:
		FAILMSGF("ruleset init: %s", ruleset_geterror(r, NULL));
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

bool ruleset_invoke(struct ruleset *r, struct stream *code)
{
	return ruleset_pcall(r, FUNC_INVOKE, 1, 0, code);
}

struct rpcall_state *ruleset_rpcall(
	struct ruleset *r, struct stream *code, rpcall_return_fn callback,
	void *data)
{
	const bool ok =
		ruleset_pcall(r, FUNC_RPCALL, 3, 1, code, callback, data);
	if (!ok) {
		return NULL;
	}
	return lua_touserdata(r->L, -1);
}

void ruleset_rpcall_cancel(struct rpcall_state *state)
{
	state->callback = NULL;
}

bool ruleset_update(
	struct ruleset *r, const char *modname, struct stream *code,
	const char *chunkname)
{
	return ruleset_pcall(r, FUNC_UPDATE, 3, 0, modname, code, chunkname);
}

bool ruleset_loadfile(struct ruleset *r, const char *filename)
{
	return ruleset_pcall(r, FUNC_LOADFILE, 1, 0, filename);
}

void ruleset_gc(struct ruleset *restrict r)
{
	lua_gc(r->L, LUA_GCCOLLECT, 0);
}

static struct dialreq *dispatch_req(
	struct ruleset *restrict r, const char *func, const char *request,
	const char *username, const char *password)
{
	lua_State *restrict L = r->L;
	const bool ok = ruleset_pcall(
		r, FUNC_REQUEST, 4, 1, (void *)func, (void *)request,
		(void *)username, (void *)password);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_touserdata(L, -1);
}

struct dialreq *ruleset_resolve(
	struct ruleset *r, const char *request, const char *username,
	const char *password)
{
	return dispatch_req(r, "resolve", request, username, password);
}

struct dialreq *ruleset_route(
	struct ruleset *r, const char *request, const char *username,
	const char *password)
{
	return dispatch_req(r, "route", request, username, password);
}

struct dialreq *ruleset_route6(
	struct ruleset *r, const char *request, const char *username,
	const char *password)
{
	return dispatch_req(r, "route6", request, username, password);
}

void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s)
{
	*s = r->vmstats;
}

const char *
ruleset_stats(struct ruleset *restrict r, const double dt, size_t *len)
{
	lua_State *restrict L = r->L;
	const char *func = "stats";
	const bool ok =
		ruleset_pcall(r, FUNC_STATS, 2, 1, (void *)func, (void *)&dt);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_geterror(r, NULL));
		return NULL;
	}
	return lua_tolstring(L, -1, len);
}

#endif /* WITH_RULESET */
