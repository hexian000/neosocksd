/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/api.h"

#include "api_client.h"
#include "conf.h"
#include "proto/domain.h"
#include "resolver.h"
#include "ruleset/base.h"
#include "server.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"
#include "net/addr.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/minmax.h"
#include "utils/serialize.h"

#include <arpa/inet.h>
#include <ev.h>
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
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	struct dialreq *restrict req = lua_touserdata(L, -1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	const struct ruleset *restrict r = aux_getruleset(L);
	api_client_invoke(r->loop, req, code, len, r->conf, r->resolver);
	return 0;
}

/* neosocksd.resolve(host) */
static int api_resolve(lua_State *restrict L)
{
	const char *restrict name = luaL_checkstring(L, 1);
	const struct ruleset *restrict r = aux_getruleset(L);
	union sockaddr_max addr;
	if (!sa_resolve_tcp(&addr, name, NULL, r->conf->resolve_pf)) {
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
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&in));
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
	const uint_least8_t *addr = (const void *)&in6;
#if LUA_32BITS
	lua_pushinteger(L, (lua_Integer)read_uint32(addr));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 4));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 8));
	lua_pushinteger(L, (lua_Integer)read_uint32(addr + 12));
	return 4;
#else
	lua_pushinteger(L, (lua_Integer)read_uint64(addr));
	lua_pushinteger(L, (lua_Integer)read_uint64(addr + 8));
	return 2;
#endif
}

/* neosocksd.setinterval(interval) */
static int api_setinterval(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	double interval = lua_tonumber(L, 1);

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
	const char *restrict s = luaL_checklstring(L, 1, &len);
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + CONSTSTRLEN(":65535")) {
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
	const struct ruleset *restrict r = aux_getruleset(L);
	const struct config *restrict conf = r->conf;
	lua_createtable(L, 0, 40);

	lua_pushstring(L, conf->listen);
	lua_setfield(L, -2, "listen");
	lua_pushstring(L, conf->forward);
	lua_setfield(L, -2, "forward");
	lua_pushstring(L, conf->proxy);
	lua_setfield(L, -2, "proxy");
	lua_pushstring(L, conf->restapi);
	lua_setfield(L, -2, "restapi");
	lua_pushstring(L, conf->http_listen);
	lua_setfield(L, -2, "http_listen");
#if WITH_RULESET
	lua_pushstring(L, conf->ruleset);
	lua_setfield(L, -2, "ruleset");
#endif
	lua_pushstring(L, conf->user_name);
	lua_setfield(L, -2, "user_name");
#if WITH_CARES
	lua_pushstring(L, conf->nameserver);
	lua_setfield(L, -2, "nameserver");
#endif
#if WITH_NETDEVICE
	lua_pushstring(L, conf->netdev);
	lua_setfield(L, -2, "netdev");
#endif

	lua_pushinteger(L, (lua_Integer)conf->loglevel);
	lua_setfield(L, -2, "loglevel");
	lua_pushinteger(L, (lua_Integer)conf->resolve_pf);
	lua_setfield(L, -2, "resolve_pf");
	lua_pushnumber(L, (lua_Number)conf->timeout);
	lua_setfield(L, -2, "timeout");
#if WITH_RULESET
	lua_pushinteger(L, (lua_Integer)conf->memlimit);
	lua_setfield(L, -2, "memlimit");
#endif

	lua_pushboolean(L, conf->auth_required);
	lua_setfield(L, -2, "auth_required");
#if WITH_SPLICE
	lua_pushboolean(L, conf->pipe);
	lua_setfield(L, -2, "pipe");
#endif
#if WITH_REUSEPORT
	lua_pushboolean(L, conf->reuseport);
	lua_setfield(L, -2, "reuseport");
#endif
#if WITH_TCP_FASTOPEN
	lua_pushboolean(L, conf->tcp_fastopen);
	lua_setfield(L, -2, "tcp_fastopen");
#endif
#if WITH_TCP_FASTOPEN_CONNECT
	lua_pushboolean(L, conf->tcp_fastopen_connect);
	lua_setfield(L, -2, "tcp_fastopen_connect");
#endif
	lua_pushboolean(L, conf->tcp_nodelay);
	lua_setfield(L, -2, "tcp_nodelay");
	lua_pushboolean(L, conf->tcp_keepalive);
	lua_setfield(L, -2, "tcp_keepalive");
#if WITH_TPROXY
	lua_pushboolean(L, conf->transparent);
	lua_setfield(L, -2, "transparent");
#endif
#if WITH_RULESET
	lua_pushboolean(L, conf->traceback);
	lua_setfield(L, -2, "traceback");
#endif
	lua_pushboolean(L, conf->conn_cache);
	lua_setfield(L, -2, "conn_cache");
	lua_pushboolean(L, conf->socks5_bind);
	lua_setfield(L, -2, "socks5_bind");
	lua_pushboolean(L, conf->socks5_udp);
	lua_setfield(L, -2, "socks5_udp");
	lua_pushboolean(L, conf->daemonize);
	lua_setfield(L, -2, "daemonize");
	lua_pushboolean(L, conf->block_loopback);
	lua_setfield(L, -2, "block_loopback");
	lua_pushboolean(L, conf->block_multicast);
	lua_setfield(L, -2, "block_multicast");
	lua_pushboolean(L, conf->block_local);
	lua_setfield(L, -2, "block_local");
	lua_pushboolean(L, conf->block_global);
	lua_setfield(L, -2, "block_global");

	lua_pushinteger(L, (lua_Integer)conf->tcp_sndbuf);
	lua_setfield(L, -2, "tcp_sndbuf");
	lua_pushinteger(L, (lua_Integer)conf->tcp_rcvbuf);
	lua_setfield(L, -2, "tcp_rcvbuf");
	lua_pushinteger(L, (lua_Integer)conf->max_sessions);
	lua_setfield(L, -2, "max_sessions");
	lua_pushinteger(L, (lua_Integer)conf->startup_limit_start);
	lua_setfield(L, -2, "startup_limit_start");
	lua_pushinteger(L, (lua_Integer)conf->startup_limit_rate);
	lua_setfield(L, -2, "startup_limit_rate");
	lua_pushinteger(L, (lua_Integer)conf->startup_limit_full);
	lua_setfield(L, -2, "startup_limit_full");
	return 1;
}

/* neosocksd.stats() */
static int api_stats(lua_State *restrict L)
{
	const struct ruleset *restrict r = aux_getruleset(L);
	struct server_stats stats = { 0 };
	uintmax_t num_dns_query = 0, num_dns_success = 0;
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
	lua_createtable(L, 0, 20);

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
	lua_pushnumber(L, (lua_Number)(clock_monotonic_ns() - stats.started));
	lua_setfield(L, -2, "uptime");
	lua_pushinteger(L, (lua_Integer)r->vmstats.byt_allocated);
	lua_setfield(L, -2, "bytes_allocated");
	lua_pushinteger(L, (lua_Integer)r->vmstats.num_object);
	lua_setfield(L, -2, "num_object");
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
