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

/* addr = format_addr_(sa) */
int format_addr_(lua_State *restrict L)
{
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

struct dialreq *make_dialreq_(lua_State *restrict L, const int n)
{
	if (n < 1) {
		return NULL;
	}
	struct dialreq *req = dialreq_new((size_t)(n - 1));
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	size_t len;
	for (int i = 1; i < n; i++) {
		const char *s = lua_tolstring(L, -i, &len);
		if (s == NULL) {
			dialreq_free(req);
			return NULL;
		}
		if (!dialreq_addproxy(req, s, len)) {
			dialreq_free(req);
			return NULL;
		}
	}
	const char *s = lua_tolstring(L, -n, &len);
	if (s == NULL) {
		dialreq_free(req);
		return NULL;
	}
	if (!dialaddr_parse(&req->addr, s, len)) {
		dialreq_free(req);
		return NULL;
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
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_CFUNCTION) != LUA_TTABLE) {
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

int ruleset_traceback_(lua_State *restrict L)
{
	const char *err = lua_tostring(L, 1);
	luaL_traceback(L, L, err, 1);
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);
	if (err == NULL) {
		LOG_TXT(VERBOSE, s, len, "Lua traceback");
		LOG_STACK(VERBOSE, 0, "C traceback");
		return 1;
	}
	LOG_TXT_F(VERBOSE, s, len, "Lua traceback for `%s'", err);
	LOG_STACK_F(VERBOSE, 0, "C traceback for `%s'", err);
	return 1;
}

bool ruleset_resume(struct ruleset *restrict r, const void *ctx, int narg, ...)
{
	check_memlimit(r);
	lua_State *restrict L = r->L;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	lua_rawgetp(L, -1, ctx);
	lua_State *restrict co = lua_tothread(L, -1);
	if (co == NULL) {
		lua_pushfstring(L, "async context lost: %p", ctx);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
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
