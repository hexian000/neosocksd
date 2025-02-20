/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "base.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "dialer.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct ruleset *aux_getruleset(lua_State *restrict L)
{
	void *ud;
	(void)lua_getallocf(L, &ud);
	return ud;
}

void aux_newweaktable(lua_State *restrict L, const char *mode)
{
	lua_newtable(L);
	lua_newtable(L);
	lua_pushstring(L, mode);
	lua_setfield(L, -2, "__mode");
	lua_setmetatable(L, -2);
}

void aux_toclose(
	lua_State *restrict L, int idx, const char *tname,
	const lua_CFunction close)
{
	idx = lua_absindex(L, idx);
	if (luaL_newmetatable(L, tname)) {
		lua_pushcfunction(L, close);
		lua_setfield(L, -2, "__close");
		lua_pushcfunction(L, close);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, idx);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, idx);
#endif
}

void aux_close(lua_State *restrict L, int idx)
{
#if HAVE_LUA_TOCLOSE
	UNUSED(L);
	UNUSED(idx);
#else
	idx = lua_absindex(L, idx);
	if (!lua_getmetatable(L, idx)) {
		return;
	}
	lua_getfield(L, -1, "__close");
	lua_pushvalue(L, idx);
	lua_call(L, 1, 0);
	lua_pushnil(L);
	lua_copy(L, -1, idx);
	lua_pop(L, 2);
#endif
}

void aux_getregtable(lua_State *restrict L, const int ridx)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, ridx) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
}

const char *aux_reader(lua_State *restrict L, void *ud, size_t *restrict sz)
{
	UNUSED(L);
	struct stream *s = ud;
	const void *buf;
	*sz = SIZE_MAX; /* Lua allows arbitrary length */
	const int err = stream_direct_read(s, &buf, sz);
	if (err != 0) {
		LOGE_F("read_stream: error %d", err);
	}
	if (*sz == 0) {
		return NULL;
	}
	return buf;
}

/* addr = format_addr(sa) */
int aux_format_addr(lua_State *restrict L)
{
	/* lua stack: ... sa */
	const struct sockaddr *restrict sa = lua_touserdata(L, -1);
	if (sa == NULL) {
		return 0;
	}
	const int af = sa->sa_family;
	switch (af) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in *)sa)->sin_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			return luaL_error(L, "inet_ntop: %s", strerror(errno));
		}
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			return luaL_error(L, "inet_ntop: %s", strerror(errno));
		}
		lua_pushstring(L, addr_str);
	} break;
	default:
		return luaL_error(L, "unknown af: %d", af);
	}
	return 1;
}

bool aux_todialreq(lua_State *restrict L, const int n)
{
	/* lua stack: ... addr proxyN ... proxy1 */
	if (n < 1) {
		lua_pushlightuserdata(L, NULL);
		return true;
	}
	if (lua_isnil(L, -1)) {
		lua_pop(L, n);
		lua_pushlightuserdata(L, NULL);
		return true;
	}
	struct dialreq *restrict req = dialreq_new((size_t)(n - 1));
	if (req == NULL) {
		LOGOOM();
		lua_pop(L, n);
		return false;
	}
	size_t len;
	for (int i = 1; i < n; i++) {
		const char *restrict s = lua_tolstring(L, -i, &len);
		if (s == NULL) {
			dialreq_free(req);
			lua_pop(L, n);
			return false;
		}
		if (!dialreq_addproxy(req, s, len)) {
			dialreq_free(req);
			lua_pop(L, n);
			return false;
		}
	}
	const char *restrict s = lua_tolstring(L, -n, &len);
	if (s == NULL) {
		dialreq_free(req);
		lua_pop(L, n);
		return false;
	}
	if (!dialaddr_parse(&req->addr, s, len)) {
		dialreq_free(req);
		lua_pop(L, n);
		return false;
	}
	lua_pop(L, n);
	lua_pushlightuserdata(L, req);
	return true;
}

int aux_traceback(lua_State *restrict L)
{
	const int type = lua_type(L, -1);
	const char *err;
	switch (type) {
	case LUA_TNIL:
		err = "(nil)";
		break;
	case LUA_TNUMBER:
	case LUA_TSTRING:
		err = lua_tostring(L, -1);
		break;
	default:
		err = lua_pushfstring(
			L, "(%s: %p)", lua_typename(L, type),
			lua_topointer(L, -1));
	}
	LOG_STACK_F(VERBOSE, 0, "traceback: %s", err);
	luaL_traceback(L, L, err, 1);
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);
	LOG_TXT_F(VERBOSE, s, len, "traceback: %s", err);
	return 1;
}

static int thread_main_k(lua_State *L, int status, lua_KContext ctx);

static int
thread_call_k(lua_State *restrict L, int status, const lua_KContext ctx)
{
	/* lua stack: errfunc? finish ? ... */
	int errfunc = 0;
	struct ruleset *restrict r = aux_getruleset(L);
	if (r->config.traceback) {
		lua_pushcfunction(L, aux_traceback);
		lua_replace(L, 1);
		errfunc = 1;
	}
	const int n = lua_gettop(L);
	const int nargs = n - 2;
	ASSERT(nargs >= 1);
	lua_pushboolean(L, (status == LUA_OK || status == LUA_YIELD));
	lua_replace(L, 3);
	if (lua_isfunction(L, 2)) {
		status = lua_pcall(L, nargs, 0, errfunc);
		if (status != LUA_OK && status != LUA_YIELD) {
			lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		}
	}

	/* cache the thread for reuse */
	aux_getregtable(L, RIDX_IDLE_THREAD);
	lua_pushthread(L);
	lua_pushboolean(L, 1);
	lua_rawset(L, -3);
	lua_settop(L, 0);
	return lua_yieldk(L, 0, ctx, thread_main_k);
}

static int
thread_main_k(lua_State *restrict L, int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	/* lua stack: errfunc finish ? func ... */
	const int errfunc = lua_isfunction(L, 1) ? 1 : 0;
	const int n = lua_gettop(L);
	const int nargs = n - 4;
	ASSERT(nargs >= 0);
	status = lua_pcallk(L, nargs, LUA_MULTRET, errfunc, ctx, thread_call_k);
	return thread_call_k(L, status, ctx);
}

static int thread_main(lua_State *restrict L)
{
	return lua_yieldk(L, 0, 0, thread_main_k);
}

/* [-0, +1, v] */
lua_State *aux_getthread(lua_State *restrict L)
{
	aux_getregtable(L, RIDX_IDLE_THREAD);
	lua_pushnil(L);
	if (lua_next(L, -2)) {
		lua_pop(L, 1);
		lua_pushvalue(L, -1);
		lua_pushnil(L);
		/* lua stack: RIDX_IDLE_THREAD co co nil */
		lua_rawset(L, -4);
		lua_replace(L, -2);
		return lua_tothread(L, -1);
	}
	lua_pop(L, 1);
	lua_State *restrict co = lua_newthread(L);
	lua_pushcfunction(co, thread_main);
	const int status = aux_resume(co, L, 0);
	ASSERT(status == LUA_YIELD);
	UNUSED(status);
	return co;
}

int aux_resume(lua_State *restrict L, lua_State *restrict from, const int narg)
{
	int status, nres;
#if LUA_VERSION_NUM >= 504
	status = lua_resume(L, from, narg, &nres);
#else
	status = lua_resume(L, from, narg);
#endif
	return status;
}

int aux_async(
	lua_State *restrict L, lua_State *restrict from, const int narg,
	const int finishidx)
{
	struct ruleset *restrict r = aux_getruleset(L);
	if (r->config.traceback) {
		lua_pushcfunction(L, aux_traceback);
	} else {
		lua_pushnil(L);
	}
	lua_pushvalue(from, finishidx);
	lua_xmove(from, L, 1);
	lua_pushnil(L);
	lua_xmove(from, L, 1 + narg);
	return aux_resume(L, from, 4 + narg);
}

static bool ruleset_pcallv(
	struct ruleset *restrict r, const lua_CFunction func, const int nargs,
	const int nresults, va_list args)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	int errfunc = 0;
	if (r->config.traceback) {
		lua_pushcfunction(L, aux_traceback);
		errfunc = 1;
	}
	lua_pushcfunction(L, func);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(args, void *));
	}
	if (lua_pcall(L, nargs, nresults, errfunc) != LUA_OK) {
		lua_pushvalue(L, -1);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	return true;
}

bool ruleset_pcall(
	struct ruleset *restrict r, const lua_CFunction func, const int nargs,
	const int nresults, ...)
{
	va_list args;
	va_start(args, nresults);
	const bool result = ruleset_pcallv(r, func, nargs, nresults, args);
	va_end(args);
	return result;
}

void ruleset_resume(struct ruleset *restrict r, void *ctx, const int narg, ...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pop(L, 1);
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return;
	}
	lua_rawgetp(L, -1, ctx);
	lua_State *restrict co = lua_tothread(L, -1);
	if (co == NULL) {
		lua_pop(L, 2);
		LOGD_F("async context lost: %p", ctx);
		return;
	}
	lua_replace(L, 1);
	va_list args;
	va_start(args, narg);
	for (int i = 0; i < narg; i++) {
		lua_pushlightuserdata(co, va_arg(args, void *));
	}
	va_end(args);
	const int status = aux_resume(co, NULL, narg);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_rawseti(co, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	}
}
