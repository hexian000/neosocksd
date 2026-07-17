/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/base.h"

#include "dialer.h"
#include "util.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <lauxlib.h>
#include <lua.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

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
	(void)L;
	(void)idx;
#else /* HAVE_LUA_TOCLOSE */
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
#endif /* HAVE_LUA_TOCLOSE */
}

void aux_getregtable(lua_State *restrict L, const int ridx)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, ridx) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
}

void aux_setsandboxenv(lua_State *restrict L)
{
	lua_newtable(L);
	lua_newtable(L);
	aux_getregtable(L, LUA_RIDX_GLOBALS);
	/* lua stack: ... chunk env mt _G */
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
	const char *const upvalue = lua_setupvalue(L, -2, 1);
	ASSERT(upvalue != NULL && strcmp(upvalue, "_ENV") == 0);
	(void)upvalue;
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
	/* thread transitions from active to idle -- decrement only after the
	 * caching above succeeds. aux_getregtable may raise ERR_BAD_REGISTRY
	 * and unwind out of lua_resume; the callers then treat the non-OK
	 * status as "died without reaching here" and decrement themselves, so
	 * decrementing before it would double-count. */
	r->vmstats.num_thread_active--;
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
	struct ruleset *restrict r = aux_getruleset(L);
	aux_getregtable(L, RIDX_IDLE_THREAD);
	lua_pushnil(L);
	lua_State *restrict co;
	if (lua_next(L, -2)) {
		lua_pop(L, 1);
		lua_pushvalue(L, -1);
		lua_pushnil(L);
		/* lua stack: RIDX_IDLE_THREAD co co nil */
		lua_rawset(L, -4);
		lua_replace(L, -2);
		co = lua_tothread(L, -1);
	} else {
		lua_pop(L, 1);
		co = lua_newthread(L);
		lua_pushcfunction(co, thread_main);
		const int status = aux_resume(co, L, 0);
		ASSERT(status == LUA_YIELD);
		(void)status;
	}
	r->vmstats.num_thread_active++;
	if (r->vmstats.num_thread_active > r->vmstats.num_thread_peak) {
		r->vmstats.num_thread_peak = r->vmstats.num_thread_active;
	}
	return co;
}

struct aux_reader_state {
	struct stream *stream;
	int err;
};

static const char *
aux_reader(lua_State *restrict L, void *ud, size_t *restrict sz)
{
	(void)L;
	struct aux_reader_state *restrict rs = ud;
	const void *buf;
	/* Lua allows arbitrary length. */
	*sz = SIZE_MAX;
	const int err = stream_direct_read(rs->stream, &buf, sz);
	if (err != 0) {
		LOGE_F("read_stream: error %d", err);
		/* lua_Reader has no error channel; record it and stop so
		 * aux_load() can turn it into a load failure instead of letting
		 * lua_load() treat the truncated input as a clean EOF. */
		rs->err = err;
		return NULL;
	}
	if (*sz == 0) {
		return NULL;
	}
	return buf;
}

int aux_load(
	lua_State *restrict L, struct stream *restrict stream,
	const char *restrict chunkname)
{
	struct aux_reader_state rs = { .stream = stream, .err = 0 };
	const int status = lua_load(L, aux_reader, &rs, chunkname, "t");
	if (status != LUA_OK) {
		/* compile error: message is already on the stack */
		return status;
	}
	if (rs.err != 0) {
		/* the chunk lua_load() compiled is truncated by a read error */
		lua_pop(L, 1);
		lua_pushfstring(L, "read error (%d)", rs.err);
		return LUA_ERRERR;
	}
	return LUA_OK;
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
			const int err = errno;
			return luaL_error(
				L, "inet_ntop: (%d) %s", err, strerror(err));
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
			return luaL_error(
				L, "inet_ntop: (%d) %s", err, strerror(err));
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
	ASSERT(n > 0);
	/* lua stack: ... addr proxyN ... proxy1 */
	if (lua_isnil(L, -n)) {
		/* a nil address means a direct connection (NULL dialreq) */
		lua_pop(L, n);
		lua_pushlightuserdata(L, NULL);
		return true;
	}
	if (n > 255) {
		lua_pop(L, n);
		return false;
	}
	struct {
		const char *restrict s;
		size_t len;
	} addr[n];
	for (int i = 0; i < n; i++) {
		addr[i].s = lua_tolstring(L, i - n, &addr[i].len);
		if (addr[i].s == NULL || addr[i].len > 1024) {
			lua_pop(L, n);
			return false;
		}
	}

	/* no lua errors now */
	struct ruleset *restrict const r = aux_getruleset(L);
	struct dialreq *restrict req = dialreq_new(r->basereq, (size_t)(n - 1));
	if (req == NULL) {
		LOGOOM();
		lua_pop(L, n);
		return false;
	}
	for (int i = n - 1; i > 0; i--) {
		if (!dialreq_addproxy(req, addr[i].s, addr[i].len)) {
			dialreq_free(req);
			lua_pop(L, n);
			return false;
		}
	}
	if (!dialaddr_parse(&req->addr, addr[0].s, addr[0].len)) {
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
	LOG_TXT_F(VERBOSE, s, len, 0, "traceback: %s", err);
	return 1;
}

int aux_resume(lua_State *restrict L, lua_State *restrict from, const int narg)
{
	int status;
#if LUA_VERSION_NUM >= 504
	int nres;
	status = lua_resume(L, from, narg, &nres);
#else
	status = lua_resume(L, from, narg);
#endif
	return status;
}

void aux_setforward(lua_State *L, lua_State *co, void *state)
{
	aux_getregtable(L, RIDX_FORWARD_CONTEXT);
	if (state != NULL) {
		lua_pushlightuserdata(L, state);
	} else {
		lua_pushnil(L);
	}
	lua_rawsetp(L, -2, co);
	lua_pop(L, 1);
}

void *aux_getforward(lua_State *restrict L)
{
	aux_getregtable(L, RIDX_FORWARD_CONTEXT);
	lua_rawgetp(L, -1, L);
	void *const state = lua_touserdata(L, -1);
	lua_pop(L, 2);
	return state;
}

/* Remove a pointer-keyed entry from a registry table without raising, for use
 * on failure paths where raising would be unsafe. A missing/corrupt table is
 * treated as "nothing to clear". */
static void
clear_context_entry(lua_State *restrict L, const int ridx, const void *key)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, ridx) == LUA_TTABLE) {
		lua_pushnil(L);
		lua_rawsetp(L, -2, key);
	}
	lua_pop(L, 1);
}

int aux_async(
	lua_State *restrict L, lua_State *restrict from, const int narg,
	const int finishidx)
{
	struct ruleset *restrict r = aux_getruleset(L);
	/* grow the coroutine stack for errfunc + finish + placeholder + func +
	 * narg args before the lua_xmove()s below, which do not grow the target
	 * and whose bounds assert is compiled out in release builds. narg is
	 * caller-controlled via neosocksd.async(). */
	if (!lua_checkstack(L, narg + 4)) {
		r->vmstats.num_thread_active--;
		clear_context_entry(from, RIDX_FORWARD_CONTEXT, L);
		return luaL_error(from, "async: too many arguments");
	}
	if (r->config.traceback) {
		lua_pushcfunction(L, aux_traceback);
	} else {
		lua_pushnil(L);
	}
	lua_pushvalue(from, finishidx);
	lua_xmove(from, L, 1);
	lua_pushnil(L);
	lua_xmove(from, L, 1 + narg);
	const int status = aux_resume(L, from, 4 + narg);
	if (status != LUA_OK && status != LUA_YIELD) {
		/* catastrophic failure: thread died without passing through
		 * thread_call_k, so its bookkeeping was never cleared. Drop the
		 * active count and remove the forward-context entry keyed by the
		 * coroutine pointer, so a later lua_newthread() reusing that
		 * address cannot alias a stale ruleset_state. */
		r->vmstats.num_thread_active--;
		clear_context_entry(from, RIDX_FORWARD_CONTEXT, L);
	}
	return status;
}

static void record_event_time(
	struct ruleset *restrict r, const int_fast64_t time_used,
	const int_fast64_t time_end)
{
	const size_t idx =
		r->vmstats.num_events++ % ARRAY_SIZE(r->vmstats.event_ns);
	r->vmstats.event_ns[idx] = (int_least64_t)time_used;
	r->vmstats.event_end[idx] = (int_least64_t)time_end;
	r->vmstats.time_total += (uint_least64_t)time_used;
}

static bool ruleset_pcallv(
	const struct ruleset *restrict r, const lua_CFunction func,
	const int nargs, const int nresults, va_list *args)
{
	lua_State *restrict const L = r->L;
	lua_settop(L, 0);
	int errfunc = 0;
	if (r->config.traceback) {
		lua_pushcfunction(L, aux_traceback);
		errfunc = 1;
	}
	lua_pushcfunction(L, func);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(*args, void *));
	}
	if (lua_pcall(L, nargs, nresults, errfunc) != LUA_OK) {
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		return false;
	}
	return true;
}

bool ruleset_pcall(
	struct ruleset *restrict r, const lua_CFunction func, const int nargs,
	const int nresults, ...)
{
	const int_fast64_t time_begin = clock_monotonic_ns();
	va_list args;
	va_start(args, nresults);
	const bool result = ruleset_pcallv(r, func, nargs, nresults, &args);
	va_end(args);
	const int_fast64_t time_end = clock_monotonic_ns();
	record_event_time(r, time_end - time_begin, time_end);
	return result;
}

void ruleset_resume(struct ruleset *restrict r, void *ctx, const int narg, ...)
{
	const int_fast64_t time_begin = clock_monotonic_ns();
	lua_State *restrict const L = r->L;
	lua_settop(L, 0);
	va_list args;
	va_start(args, narg);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT) !=
	    LUA_TTABLE) {
		lua_pop(L, 1);
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		va_end(args);
		return;
	}
	lua_rawgetp(L, -1, ctx);
	lua_State *restrict const co = lua_tothread(L, -1);
	if (co == NULL) {
		lua_pop(L, 2);
		LOGD_F("async context lost: %p", ctx);
		va_end(args);
		return;
	}
	lua_replace(L, 1);
	for (int i = 0; i < narg; i++) {
		lua_pushlightuserdata(co, va_arg(args, void *));
	}
	va_end(args);
	const int status = aux_resume(co, NULL, narg);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_rawseti(co, LUA_REGISTRYINDEX, RIDX_LASTERROR);
		/* catastrophic failure: thread died without passing through
		 * thread_call_k. Drop the active count and clear the registry
		 * entries keyed by the abandoned coroutine (forward context) and
		 * the async userdata (await context), so a reused pointer cannot
		 * alias a stale entry. */
		r->vmstats.num_thread_active--;
		clear_context_entry(L, RIDX_FORWARD_CONTEXT, co);
		clear_context_entry(L, RIDX_AWAIT_CONTEXT, ctx);
	}
	const int_fast64_t time_end = clock_monotonic_ns();
	record_event_time(r, time_end - time_begin, time_end);
}
