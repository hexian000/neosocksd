/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api.h"

#include "base.h"

#include "net/addr.h"
#include "utils/minmax.h"
#include "utils/serialize.h"

#include "api_client.h"
#include "conf.h"
#include "proto/domain.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* co, err = neosocksd.async(finish, func, ...) */
static int api_async(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	luaL_checkany(L, 2);
	const int narg = lua_gettop(L) - 2;
	lua_State *restrict co = aux_getthread(L);
	lua_insert(L, 1);
	const int status = aux_async(co, L, narg, 2);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_pushnil(L);
		lua_xmove(co, L, 1);
		return 2;
	}
	return 1;
}

/* neosocksd.invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke(lua_State *restrict L)
{
	size_t len;
	const char *restrict code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L) - 1;
	if (!aux_todialreq(L, n)) {
		lua_pushliteral(L, ERR_INVALID_INVOKE);
		return lua_error(L);
	}
	struct dialreq *restrict req = lua_touserdata(L, -1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_INVOKE);
		return lua_error(L);
	}
	struct ruleset *restrict r = aux_getruleset(L);
	api_client_invoke(r->loop, req, code, len);
	return 0;
}

/* neosocksd.resolve(host) */
static int api_resolve(lua_State *restrict L)
{
	const char *restrict name = luaL_checkstring(L, 1);
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
	const char *restrict s = lua_tostring(L, 1);
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
	const char *restrict s = lua_tostring(L, 1);
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
	const char *restrict s = luaL_checklstring(L, 1, &len);
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
	struct ruleset *restrict r = aux_getruleset(L);
	lua_createtable(L, 0, 9);

	lua_pushinteger(L, (lua_Integer)conf->log_level);
	lua_setfield(L, -2, "loglevel");
	lua_pushnumber(L, (lua_Number)conf->timeout);
	lua_setfield(L, -2, "timeout");
	lua_pushboolean(L, conf->auth_required);
	lua_setfield(L, -2, "auth_required");
	lua_pushboolean(L, r->config.memlimit_kb);
	lua_setfield(L, -2, "memlimit");
	lua_pushboolean(L, r->config.traceback);
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
	struct ruleset *restrict r = aux_getruleset(L);
	struct server_stats stats = { 0 };
	{
		const struct server *restrict s = G.server;
		if (s != NULL) {
			stats = s->stats;
		}
	}
	lua_createtable(L, 0, 9);

	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	lua_setfield(L, -2, "lasterror");
	lua_pushinteger(L, (lua_Integer)stats.num_halfopen);
	lua_setfield(L, -2, "num_halfopen");
	lua_pushinteger(L, (lua_Integer)stats.num_sessions);
	lua_setfield(L, -2, "num_sessions");
	lua_pushinteger(L, (lua_Integer)stats.byt_up);
	lua_setfield(L, -2, "byt_up");
	lua_pushinteger(L, (lua_Integer)stats.byt_down);
	lua_setfield(L, -2, "byt_down");
	lua_pushnumber(L, (lua_Number)(ev_now(r->loop) - stats.started));
	lua_setfield(L, -2, "uptime");
	lua_pushinteger(L, (lua_Integer)r->vmstats.byt_allocated);
	lua_setfield(L, -2, "bytes_allocated");
	lua_pushinteger(L, (lua_Integer)r->vmstats.num_object);
	lua_setfield(L, -2, "num_object");
	return 1;
}

/* neosocksd.now() */
static int api_now(lua_State *restrict L)
{
	struct ruleset *restrict r = aux_getruleset(L);
	const ev_tstamp now = ev_now(r->loop);
	lua_pushnumber(L, (lua_Number)now);
	return 1;
}

/* neosocksd.traceback() */
static int api_traceback(lua_State *restrict L)
{
	return aux_traceback(L);
}

int luaopen_neosocksd(lua_State *restrict L)
{
	const luaL_Reg apilib[] = {
		{ "async", api_async },
		{ "config", api_config },
		{ "invoke", api_invoke },
		{ "now", api_now },
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
