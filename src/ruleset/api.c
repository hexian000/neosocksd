/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api.h"

#include "net/addr.h"
#include "utils/minmax.h"
#include "utils/serialize.h"

#include "api_client.h"
#include "conf.h"
#include "proto/domain.h"
#include "ruleset/base.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

#include <arpa/inet.h>

#include <math.h>
#include <stddef.h>
#include <time.h>

/* neosocksd.invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke(lua_State *restrict L)
{
	size_t len;
	const char *code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L) - 1;
	struct dialreq *req = aux_todialreq(L, n);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ROUTE);
		return lua_error(L);
	}
	struct ruleset *restrict r = aux_getruleset(L);
	struct api_client_cb cb = { NULL, NULL };
	api_client_do(r->loop, req, "/ruleset/invoke", code, len, cb);
	return 0;
}

/* neosocksd.resolve(host) */
static int api_resolve(lua_State *restrict L)
{
	const char *name = luaL_checkstring(L, 1);
	union sockaddr_max addr;
	if (!resolve_addr(&addr, name, NULL, G.conf->resolve_pf)) {
		return 0;
	}
	lua_pushlightuserdata(L, &addr.sa);
	return aux_format_addr(L);
}

/* neosocksd.parse_ipv4(ipv4) */
static int api_parse_ipv4(lua_State *restrict L)
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
static int api_parse_ipv6(lua_State *restrict L)
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

/* neosocksd.setinterval(interval) */
static int api_setinterval(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	double interval = lua_tonumber(L, 1);

	struct ruleset *restrict r = aux_getruleset(L);
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
static int api_splithostport(lua_State *restrict L)
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
static int api_config(lua_State *restrict L)
{
	const struct config *restrict conf = G.conf;
	lua_createtable(L, 0, 16);

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
static int api_stats(lua_State *restrict L)
{
	struct server *restrict s = G.server;
	if (s == NULL) {
		return 0;
	}
	struct ruleset *restrict r = aux_getruleset(L);
	const struct server_stats *restrict stats = &s->stats;
	lua_createtable(L, 0, 16);

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

#if HAVE_CLOCK_GETTIME
/* neosocksd.clock() */
static int api_clock(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}

/* neosocksd.time() */
static int api_time(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}
#endif /* HAVE_CLOCK_GETTIME */

/* neosocksd.now() */
static int api_now(lua_State *restrict L)
{
	struct ruleset *restrict r = aux_getruleset(L);
	const ev_tstamp now = ev_now(r->loop);
	lua_pushnumber(L, (lua_Number)now);
	return 1;
}

static int api_traceback(lua_State *restrict L)
{
	return aux_traceback(L);
}

int luaopen_neosocksd(lua_State *restrict L)
{
	const luaL_Reg apilib[] = {
		{ "config", api_config },
		{ "invoke", api_invoke },
		{ "now", api_now },
#if HAVE_CLOCK_GETTIME
		{ "clock", api_clock },
		{ "monotonic", api_time },
#endif
		{ "parse_ipv4", api_parse_ipv4 },
		{ "parse_ipv6", api_parse_ipv6 },
		{ "resolve", api_resolve },
		{ "setinterval", api_setinterval },
		{ "splithostport", api_splithostport },
		{ "stats", api_stats },
		{ "traceback", api_traceback },
		{ NULL, NULL },
	};
	luaL_newlib(L, apilib);
	return 1;
}
