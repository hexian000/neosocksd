/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "base.h"

#include "compat.h"

#include "io/stream.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset.h"
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

int format_addr_(lua_State *restrict L)
{
	const struct sockaddr *sa = lua_topointer(L, -1);
	if (sa == NULL) {
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
			lua_pushstring(L, strerror(err));
			return lua_error(L);
		}
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			lua_pushstring(L, strerror(err));
			return lua_error(L);
		}
		lua_pushstring(L, addr_str);
	} break;
	default:
		return luaL_error(L, "unknown af: %d", af);
	}
	return 1;
}

const char *ruleset_reader(lua_State *L, void *ud, size_t *restrict sz)
{
	UNUSED(L);
	struct reader_status *restrict rd = ud;
	const void *buf = rd->prefix;
	if (buf != NULL) {
		*sz = rd->prefixlen;
		rd->prefix = NULL;
		rd->prefixlen = 0;
		return buf;
	}
	*sz = SIZE_MAX; /* Lua allows arbitrary length */
	const int err = stream_direct_read(rd->s, &buf, sz);
	if (err != 0) {
		LOGE_F("read_stream: error %d", err);
	}
	if (*sz == 0) {
		return NULL;
	}
	return buf;
}

struct dialreq *pop_dialreq_(lua_State *restrict L, const int n)
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
			if (!dialreq_addproxy(req, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		} else {
			if (!dialaddr_parse(&req->addr, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		}
		lua_pop(L, 1);
	}
	return req;
}

static inline void check_memlimit(struct ruleset *restrict r)
{
	const size_t memlimit = G.conf->memlimit;
	if (memlimit == 0 || (r->vmstats.byt_allocated >> 20u) < memlimit) {
		return;
	}
	ruleset_gc(r);
}

bool ruleset_pcall(
	struct ruleset *restrict r, int func, int nargs, int nresults, ...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FUNCTIONS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return false;
	}
	if (lua_rawgeti(L, 1, func) != LUA_TFUNCTION) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return false;
	}
	const bool traceback = G.conf->traceback;
	if (traceback) {
		if (lua_rawgeti(L, 1, FUNC_TRACEBACK) != LUA_TFUNCTION) {
			lua_pushliteral(L, ERR_BAD_REGISTRY);
			return false;
		}
		lua_replace(L, 1);
	}
	va_list args;
	va_start(args, nresults);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(args, void *));
	}
	va_end(args);
	if (lua_pcall(L, nargs, nresults, traceback ? 1 : 0) != LUA_OK) {
		lua_pushvalue(L, -1);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	return true;
}

int thread_main_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	UNUSED(ctx);
	if (lua_isnil(L, lua_upvalueindex(1))) {
		if (status != LUA_OK && status != LUA_YIELD) {
			LOGW_F("async error: %s", lua_tostring(L, -1));
			lua_pushvalue(L, -1);
			lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		}
		return 0;
	}
	/* stack: FUNC_TRACEBACK?, true, ... */
	const int n = lua_gettop(L) - 1;
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_replace(L, 1);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_pushboolean(L, 0);
		lua_replace(L, 2);
	}
	/* lua stack: f ok ... */
	lua_call(L, n, 0);
	return 0;
}

static int push_traceback_(lua_State *restrict L)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FUNCTIONS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	if (lua_rawgeti(L, -1, FUNC_TRACEBACK) != LUA_TFUNCTION) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	lua_replace(L, -2);
	return 1;
}

/* thread_main(f, ...) */
int thread_main_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	const int n = lua_gettop(L) - 1;
	const int errfunc = G.conf->traceback ? 1 : 0;
	if (errfunc) {
		(void)push_traceback_(L);
	} else {
		lua_pushnil(L);
	}
	lua_pushboolean(L, 1);
	lua_rotate(L, 1, 2);
	/* FUNC_TRACEBACK?, true, f, ... */
	const int status =
		lua_pcallk(L, n, LUA_MULTRET, errfunc, 0, thread_main_k_);
	return thread_main_k_(L, status, 0);
}

bool ruleset_resume(struct ruleset *restrict r, const void *ctx, int narg, ...)
{
	check_memlimit(r);
	lua_State *restrict L = r->L;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_CONTEXTS) != LUA_TTABLE) {
		LOGE(ERR_BAD_REGISTRY);
		return false;
	}
	lua_rawgetp(L, -1, ctx);
	lua_State *restrict co = lua_tothread(L, -1);
	if (co == NULL) {
		LOGE_F("async context lost: %p", ctx);
		return false;
	}
	lua_pop(L, 2);
	va_list args;
	va_start(args, narg);
	for (int i = 0; i < narg; i++) {
		lua_pushlightuserdata(co, va_arg(args, void *));
	}
	va_end(args);
	int nres;
	const int status = co_resume(co, L, narg, &nres);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_pushvalue(co, -1);
		lua_rawseti(co, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	return true;
}
