/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api.h"

#include "api_client.h"
#include "base.h"
#include "conf.h"
#include "proto/domain.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "binary/serialize.h"
#include "net/addr.h"
#include "os/clock.h"
#include "os/socket.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* co, err = neosocksd.async(finish, func, ...) */
static int api_async(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	luaL_checkany(L, 2);
	const int narg = lua_gettop(L) - 2;
	lua_State *restrict const co = aux_getthread(L);
	lua_insert(L, 1);
	const int status = aux_async(co, L, narg, 2);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_pushnil(L);
		lua_xmove(co, L, 1);
		return 2;
	}
	/* aux_async consumed func and its args, leaving [co, finish]; drop the
	 * leftover finish so the returned value is co (the coroutine) */
	lua_settop(L, 1);
	return 1;
}

/* neosocksd.invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke(lua_State *restrict L)
{
	size_t len;
	const char *restrict code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L) - 1;
	if (n <= 0 || !aux_todialreq(L, n)) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	struct dialreq *restrict const req = lua_touserdata(L, -1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	const struct ruleset *restrict r = aux_getruleset(L);
	const struct api_client_opts opts = {
		.conf = r->conf,
		.resolver = r->resolver,
		.stats = r->server != NULL ? &r->server->stats : NULL,
	};
	api_client_invoke(r->loop, req, code, len, &opts);
	return 0;
}

/* neosocksd.resolve(host) */
static int api_resolve(lua_State *restrict L)
{
	size_t len;
	const char *restrict const name = luaL_checklstring(L, 1, &len);
	if (memchr(name, '\0', len) != NULL) {
		return luaL_error(L, "string contains an embedded NUL byte");
	}
	const struct ruleset *restrict r = aux_getruleset(L);
	union sockaddr_max addr;
	if (!sa_resolve(
		    &addr, name, NULL, SA_RESOLVE_TCP, r->conf->resolve_pf)) {
		return 0;
	}
	lua_pushlightuserdata(L, &addr.sa);
	return aux_format_addr(L);
}

/* neosocksd.parse_ipv4(ipv4) */
static int api_parse_ipv4(lua_State *restrict L)
{
	size_t len;
	const char *restrict const s = lua_tolstring(L, 1, &len);
	if (s == NULL) {
		return 0;
	}
	if (memchr(s, '\0', len) != NULL) {
		return luaL_error(L, "string contains an embedded NUL byte");
	}
	struct in_addr in;
	if (inet_pton(AF_INET, s, &in) != 1) {
		return 0;
	}
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&in));
	return 1;
}

/* neosocksd.parse_ipv6(ipv6) */
static int api_parse_ipv6(lua_State *restrict L)
{
	size_t len;
	const char *restrict const s = lua_tolstring(L, 1, &len);
	if (s == NULL) {
		return 0;
	}
	if (memchr(s, '\0', len) != NULL) {
		return luaL_error(L, "string contains an embedded NUL byte");
	}
	struct in6_addr in6;
	if (inet_pton(AF_INET6, s, &in6) != 1) {
		return 0;
	}
	const uint_least8_t *const addr = (const void *)&in6;
#if LUA_32BITS
	lua_pushinteger(L, (lua_Integer)read_uint32(addr));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 4));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 8));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 12));
	return 4;
#else /* LUA_32BITS */
	lua_pushinteger(L, (lua_Integer)read_uint64(addr));
	lua_pushinteger(L, (lua_Integer)read_uint64(addr + 8));
	return 2;
#endif /* LUA_32BITS */
}

/* neosocksd.setinterval(interval) */
static int api_setinterval(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	const double interval = lua_tonumber(L, 1);

	struct ruleset *restrict r = aux_getruleset(L);
	ev_timer_stop(r->loop, &r->w_ticker);
	ev_idle_stop(r->loop, &r->w_idle);
	if (!isnormal(interval)) {
		return 0;
	}

	if (interval < 0) {
		ev_timer_set(&r->w_ticker, 0.0, 0.0);
		ev_idle_start(r->loop, &r->w_idle);
		return 0;
	}
	ev_timer_set(&r->w_ticker, 0.0, interval);
	ev_timer_again(r->loop, &r->w_ticker);
	return 0;
}

/* neosocksd.splithostport() */
static int api_splithostport(lua_State *restrict L)
{
	size_t len;
	const char *restrict const s = luaL_checklstring(L, 1, &len);
	if (memchr(s, '\0', len) != NULL) {
		return luaL_error(L, "string contains an embedded NUL byte");
	}
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + CONSTSTRLEN(":65535")) {
		/* Format len with the standard %zu into a buffer, then pass it as
		 * %s: lua_pushfstring implements its own limited formatter that
		 * rejects %z, and its only integer form (%I) is lua_Integer, which
		 * narrows a size_t past LUA_MAXINTEGER (an int on a LUA_32BITS
		 * build) -- exactly this large-len branch. */
		char lenbuf[24]; /* fits 2^64 in decimal */
		(void)snprintf(lenbuf, sizeof(lenbuf), "%zu", len);
		(void)lua_pushfstring(L, "address too long: %s bytes", lenbuf);
		return lua_error(L);
	}
	char buf[len + 1];
	memcpy(buf, s, len);
	buf[len] = '\0';
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		/* On the request path the address is the name the peer wrote,
		 * and the daemon renders an uncaught ruleset error into one log
		 * line, so a newline in it would end that line and let the peer
		 * write the rest. Report the failure without the bytes; the
		 * caller has the address it passed. */
		return luaL_error(L, "invalid address");
	}
	lua_pushstring(L, host);
	lua_pushstring(L, port);
	return 2;
}

/* neosocksd.config([key]) */
static int api_config(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	const struct config *restrict conf = r->conf;
	if (lua_gettop(L) != 0) {
		if (lua_type(L, 1) != LUA_TSTRING) {
			lua_pushnil(L);
			return 1;
		}
		size_t len;
		const char *const key = lua_tolstring(L, 1, &len);
		if (strlen(key) != len) {
			lua_pushnil(L);
		} else if (strcmp(key, "ruleset") == 0) {
			lua_pushstring(L, conf->ruleset);
		} else if (strcmp(key, "user_name") == 0) {
			lua_pushstring(L, conf->user_name);
		} else if (strcmp(key, "daemonize") == 0) {
			lua_pushboolean(L, conf->daemonize);
		} else {
			conf_pushfield(L, conf, key);
		}
		return 1;
	}
	conf_pushtable(L, conf);
	lua_pushstring(L, conf->ruleset);
	lua_setfield(L, -2, "ruleset");
	lua_pushstring(L, conf->user_name);
	lua_setfield(L, -2, "user_name");
	lua_pushboolean(L, conf->daemonize);
	lua_setfield(L, -2, "daemonize");
	return 1;
}

/* neosocksd.stats() */
static int api_stats(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	/* started defaults to the "not started" sentinel so uptime reads 0 when
	 * no server is attached yet (ruleset loads before ruleset_setserver) */
	struct server_stats stats = { .started = -1 };
	uint_fast64_t num_dns_query = 0, num_dns_success = 0;
	{
		const struct server *restrict s = r->server;
		if (s != NULL) {
			server_stats(s, &stats);
			if (s->resolver != NULL) {
				const struct resolver_stats *restrict rs =
					resolver_stats(s->resolver);
				num_dns_query = rs->num_query;
				num_dns_success = rs->num_success;
			}
		}
	}
	lua_createtable(L, 0, 22);

	lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	lua_setfield(L, -2, "lasterror");
	lua_pushinteger(L, (lua_Integer)stats.num_halfopen);
	lua_setfield(L, -2, "num_halfopen");
	lua_pushinteger(L, (lua_Integer)stats.num_sessions);
	lua_setfield(L, -2, "num_sessions");
	lua_pushinteger(L, (lua_Integer)stats.num_sessions_peak);
	lua_setfield(L, -2, "num_sessions_peak");
	lua_pushinteger(L, (lua_Integer)stats.num_request);
	lua_setfield(L, -2, "num_request");
	lua_pushinteger(L, (lua_Integer)stats.num_success);
	lua_setfield(L, -2, "num_success");
	lua_pushinteger(L, (lua_Integer)stats.num_reject_ruleset);
	lua_setfield(L, -2, "num_reject_ruleset");
	lua_pushinteger(L, (lua_Integer)stats.num_reject_timeout);
	lua_setfield(L, -2, "num_reject_timeout");
	lua_pushinteger(L, (lua_Integer)stats.num_reject_upstream);
	lua_setfield(L, -2, "num_reject_upstream");
	lua_pushinteger(L, (lua_Integer)stats.byt_up);
	lua_setfield(L, -2, "byt_up");
	lua_pushinteger(L, (lua_Integer)stats.byt_down);
	lua_setfield(L, -2, "byt_down");
	const lua_Number uptime =
		stats.started > 0 ?
			(lua_Number)(clock_monotonic_ns() - stats.started) :
			0.0;
	lua_pushnumber(L, uptime);
	lua_setfield(L, -2, "uptime");
	lua_pushinteger(L, (lua_Integer)r->vmstats.byt_allocated);
	lua_setfield(L, -2, "bytes_allocated");
	lua_pushinteger(L, (lua_Integer)r->vmstats.num_object);
	lua_setfield(L, -2, "num_object");
	lua_pushinteger(L, (lua_Integer)r->vmstats.num_thread_active);
	lua_setfield(L, -2, "num_thread_active");
	lua_pushinteger(L, (lua_Integer)r->vmstats.num_thread_peak);
	lua_setfield(L, -2, "num_thread_peak");
	lua_pushinteger(L, (lua_Integer)stats.num_accept);
	lua_setfield(L, -2, "num_accept");
	lua_pushinteger(L, (lua_Integer)stats.num_serve);
	lua_setfield(L, -2, "num_serve");
	lua_pushinteger(L, (lua_Integer)stats.num_api_request);
	lua_setfield(L, -2, "num_api_request");
	lua_pushinteger(L, (lua_Integer)stats.num_api_success);
	lua_setfield(L, -2, "num_api_success");
	lua_pushinteger(L, (lua_Integer)num_dns_query);
	lua_setfield(L, -2, "num_dns_query");
	lua_pushinteger(L, (lua_Integer)num_dns_success);
	lua_setfield(L, -2, "num_dns_success");
	return 1;
}

/* neosocksd.now() */
static int api_now(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
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
