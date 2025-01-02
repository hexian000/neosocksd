/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "base.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "conf.h"
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

void aux_pushregtable(lua_State *restrict L, const int idx)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, idx) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
}

const char *aux_reader(lua_State *L, void *ud, size_t *restrict sz)
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
	const struct sockaddr *sa = lua_touserdata(L, -1);
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
	struct dialreq *req = dialreq_new((size_t)(n - 1));
	if (req == NULL) {
		LOGOOM();
		lua_pop(L, n);
		return false;
	}
	size_t len;
	for (int i = 1; i < n; i++) {
		const char *s = lua_tolstring(L, -i, &len);
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
	const char *s = lua_tolstring(L, -n, &len);
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
	const int type = lua_type(L, 1);
	const char *err;
	switch (type) {
	case LUA_TNIL:
		err = "(nil)";
		break;
	case LUA_TNUMBER:
	case LUA_TSTRING:
		err = lua_tostring(L, 1);
		break;
	default:
		err = lua_pushfstring(
			L, "(%s: %p)", lua_typename(L, type),
			lua_topointer(L, 1));
	}
	LOG_STACK_F(WARNING, 0, "traceback: %s", err);
	luaL_traceback(L, L, err, 1);
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);
	LOG_TXT_F(VERBOSE, s, len, "traceback: %s", err);
	return 1;
}

void aux_resume(lua_State *restrict L, const int tidx, const int narg)
{
	lua_State *restrict co = lua_tothread(L, tidx);
	ASSERT(co != NULL);
	int status, nres;
#if LUA_VERSION_NUM >= 504
	status = lua_resume(co, NULL, narg, &nres);
#elif LUA_VERSION_NUM == 503
	status = lua_resume(co, NULL, narg);
	nres = lua_gettop(co);
#endif
	if (status == LUA_YIELD) {
		return;
	}
	/* routine is finished */
	aux_pushregtable(L, RIDX_ASYNC_ROUTINE);
	lua_pushvalue(L, tidx); /* co */
	if (lua_rawget(L, -2) == LUA_TNIL) {
		/* no finish function */
		return;
	}
	lua_pushvalue(L, tidx);
	lua_pushnil(L);
	/* lua stack: ... RIDX_ASYNC_ROUTINE finish co nil */
	lua_rawset(L, -4);
	int errfunc = 0;
	if (G.conf->traceback) {
		errfunc = lua_absindex(L, -2);
		lua_pushcfunction(L, aux_traceback);
		lua_replace(L, errfunc);
	}
	/* lua stack: ... traceback? finish */
	if (status != LUA_OK) {
		nres = 1;
	}
	luaL_checkstack(L, 1 + nres, NULL);
	lua_pushboolean(L, status == LUA_OK);
	lua_xmove(co, L, nres);
	/* call finish function */
	if (lua_pcall(L, 1 + nres, 0, errfunc) != LUA_OK) {
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	}
}

static bool ruleset_pcallkv(
	lua_State *restrict L, const lua_CFunction func, const int nargs,
	const int nresults, const lua_KContext ctx, const lua_KFunction kfunc,
	va_list args)
{
	int errfunc = 0;
	if (G.conf->traceback) {
		lua_pushcfunction(L, aux_traceback);
		errfunc = 1;
	}
	lua_pushcfunction(L, func);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(args, void *));
	}
	if (lua_pcallk(L, nargs, nresults, errfunc, ctx, kfunc) != LUA_OK) {
		lua_pushvalue(L, -1);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	return true;
}

static void check_memlimit(struct ruleset *restrict r)
{
	const int memlimit_mb = G.conf->memlimit;
	if (memlimit_mb <= 0) {
		return;
	}
	if (r->vmstats.byt_allocated < ((size_t)memlimit_mb << 20u)) {
		return;
	}
	(void)lua_gc(r->L, LUA_GCCOLLECT, 0);
}

bool ruleset_pcall(
	struct ruleset *restrict r, const lua_CFunction func, const int nargs,
	const int nresults, ...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
	va_list args;
	va_start(args, nresults);
	const bool result =
		ruleset_pcallkv(L, func, nargs, nresults, 0, NULL, args);
	va_end(args);
	return result;
}

bool ruleset_pcallk(
	struct ruleset *restrict r, const lua_CFunction func, const int nargs,
	const int nresults, const lua_KContext ctx, const lua_KFunction kfunc,
	...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
	va_list args;
	va_start(args, kfunc);
	const bool result =
		ruleset_pcallkv(L, func, nargs, nresults, ctx, kfunc, args);
	va_end(args);
	return result;
}

void ruleset_resume(struct ruleset *restrict r, void *ctx, const int narg, ...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
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
		lua_pushfstring(L, "async context lost: %p", ctx);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return;
	}
	lua_replace(L, 1);
	va_list args;
	va_start(args, narg);
	for (int i = 0; i < narg; i++) {
		lua_pushlightuserdata(co, va_arg(args, void *));
	}
	va_end(args);
	aux_resume(L, 1, narg);
}
