#include "ruleset.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "dialer.h"
#include "sockutil.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <arpa/inet.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ruleset {
	const struct config *conf;
	lua_State *L;
};

static int resolve(lua_State *L)
{
	if (lua_gettop(L) != 1) {
		luaL_error(L, "resolve requires 1 argument");
	}
	lua_getfield(L, LUA_REGISTRYINDEX, "ruleset");
	struct ruleset *restrict r = (struct ruleset *)lua_topointer(L, -1);
	lua_pop(L, 1);
	const char *s = lua_tostring(L, -1);
	sockaddr_max_t addr;
	if (!resolve_hostname(&addr, s, r->conf->resolve_pf)) {
		return 0;
	}
	const int af = addr.sa.sa_family;
	switch (af) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		const char *addr_str =
			inet_ntop(af, &addr.in.sin_addr, buf, sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			luaL_error(L, strerror(err));
		}
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str =
			inet_ntop(af, &addr.in6.sin6_addr, buf, sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			luaL_error(L, strerror(err));
		}
		lua_pushstring(L, addr_str);
	} break;
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

static int parse_ipv4(lua_State *L)
{
	if (lua_gettop(L) != 1) {
		luaL_error(L, "parse_ipv4 requires 1 argument");
	}
	const char *s = lua_tostring(L, -1);
	struct sockaddr_in in;
	if (inet_pton(AF_INET, s, &in) != 1) {
		return 0;
	}
	lua_pushinteger(L, ntohl(in.sin_addr.s_addr));
	return 1;
}

static int parse_ipv6(lua_State *L)
{
	if (lua_gettop(L) != 1) {
		luaL_error(L, "parse_ipv6 requires 1 argument");
	}
	const char *s = lua_tostring(L, -1);
	struct sockaddr_in6 in6;
	if (inet_pton(AF_INET6, s, &in6) != 1) {
		return 0;
	}
	lua_pushinteger(L, ntohl(in6.sin6_addr.s6_addr32[0]));
	lua_pushinteger(L, ntohl(in6.sin6_addr.s6_addr32[1]));
	lua_pushinteger(L, ntohl(in6.sin6_addr.s6_addr32[2]));
	lua_pushinteger(L, ntohl(in6.sin6_addr.s6_addr32[3]));
	return 4;
}

static int luaopen_neosocksd(lua_State *L)
{
	lua_newtable(L);
	lua_pushcfunction(L, resolve);
	lua_setfield(L, -2, "resolve");
	lua_pushcfunction(L, parse_ipv4);
	lua_setfield(L, -2, "parse_ipv4");
	lua_pushcfunction(L, parse_ipv6);
	lua_setfield(L, -2, "parse_ipv6");
	return 1;
}

struct ruleset *ruleset_new(const struct config *conf)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		ruleset_free(r);
		return NULL;
	}
	r->L = L;
	r->conf = conf;

	lua_pushlightuserdata(L, r);
	lua_setfield(L, LUA_REGISTRYINDEX, "ruleset");

	luaL_requiref(L, "_G", luaopen_base, 1);
	lua_pop(L, 1);
#ifdef LUA_MATHLIBNAME
	luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_STRLIBNAME
	luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_TABLIBNAME
	luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_DBLIBNAME
	luaL_requiref(L, LUA_DBLIBNAME, luaopen_debug, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_OSLIBNAME
	luaL_requiref(L, LUA_OSLIBNAME, luaopen_os, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_IOLIBNAME
	luaL_requiref(L, LUA_IOLIBNAME, luaopen_io, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_UTF8LIBNAME
	luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
	lua_pop(L, 1);
#endif
#ifdef LUA_COMPAT_BITLIB
	luaL_requiref(L, LUA_COMPAT_BITLIB, luaopen_bit32, 1);
	lua_pop(L, 1);
#endif

	luaL_requiref(L, "neosocksd", luaopen_neosocksd, 1);
	lua_pop(L, 1);
	return r;
}

void ruleset_free(struct ruleset *restrict r)
{
	if (r != NULL && r->L != NULL) {
		lua_close(r->L);
	}
	free(r);
}

bool ruleset_load(struct ruleset *r, const char *rulestr)
{
	LOGD_F("ruleset load: %zu bytes", strlen(rulestr));
	lua_State *restrict L = r->L;
	if (luaL_loadstring(L, rulestr) != LUA_OK) {
		LOGE_F("ruleset load: %s", lua_tostring(L, -1));
		lua_settop(L, 0);
		return false;
	}
	if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
		LOGE_F("ruleset load: %s", lua_tostring(L, -1));
		lua_settop(L, 0);
		return false;
	}
	/* user may load a patch that don't need to replace the whole ruleset object */
	if (lua_istable(L, -1)) {
		lua_setglobal(L, "ruleset");
	}
	lua_settop(L, 0);
	return true;
}

bool ruleset_loadfile(struct ruleset *r, const char *filename)
{
	lua_State *restrict L = r->L;
	if (luaL_loadfile(L, filename) != LUA_OK) {
		LOGE_F("ruleset load: %s", lua_tostring(L, -1));
		lua_settop(L, 0);
		return false;
	}
	if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
		LOGE_F("ruleset load: %s", lua_tostring(L, -1));
		lua_settop(L, 0);
		return false;
	}
	if (lua_istable(L, -1)) {
		lua_setglobal(L, "ruleset");
	}
	lua_settop(L, 0);
	return true;
}

void ruleset_gc(struct ruleset *restrict r)
{
	lua_gc(r->L, LUA_GCCOLLECT);
}

size_t ruleset_memused(struct ruleset *restrict r)
{
	size_t n = (size_t)lua_gc(r->L, LUA_GCCOUNT) << 10u;
	n |= (size_t)lua_gc(r->L, LUA_GCCOUNTB);
	return n;
}

static struct dialreq *pop_dialreq(lua_State *restrict L, int n)
{
	assert(n > 0);
	size_t len;
	const char *direct = lua_tolstring(L, -1, &len);
	struct dialaddr addr;
	if (!dialaddr_set(&addr, direct, len)) {
		LOGW("Lua script returned an invalid address");
		return NULL;
	}
	lua_pop(L, 1);
	n--;
	struct dialreq *req = dialreq_new(&addr, (size_t)n);
	if (req == NULL) {
		return NULL;
	}
	for (int i = 0; i < n; i++) {
		const char *s = lua_tolstring(L, -1, &len);
		if (s == NULL) {
			LOGE("ruleset function should return string");
			dialreq_free(req);
			lua_settop(L, 0);
			return NULL;
		}
		if (!dialreq_proxy(req, PROTO_SOCKS4A, s, len)) {
			dialreq_free(req);
			lua_settop(L, 0);
			return NULL;
		}
		lua_pop(L, 1);
	}
	return req;
}

static struct dialreq *rule_accept(const char *domain)
{
	struct dialaddr addr;
	if (!dialaddr_set(&addr, domain, strlen(domain))) {
		return NULL;
	}
	return dialreq_new(&addr, 0);
}

static struct dialreq *
ruleset_call(struct ruleset *restrict r, const char *func, const char *request)
{
	lua_State *restrict L = r->L;
	if (lua_getglobal(L, "ruleset") != LUA_TTABLE) {
		lua_settop(L, 0);
		return rule_accept(request);
	}
	if (lua_getfield(L, -1, func) != LUA_TFUNCTION) {
		lua_settop(L, 0);
		return rule_accept(request);
	}
	lua_remove(L, -2);
	(void)lua_pushstring(L, request);
	if (lua_pcall(L, 1, LUA_MULTRET, 0) != LUA_OK) {
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		lua_settop(L, 0);
		return NULL;
	}
	const int n = lua_gettop(L);
	if (n < 1) {
		return NULL;
	}
	switch (lua_type(L, -1)) {
	case LUA_TSTRING:
		break;
	case LUA_TNIL:
		lua_settop(L, 0);
		return NULL;
	default:
		LOGE_F("ruleset.%s: %s", func, lua_tostring(L, -1));
		lua_settop(L, 0);
		return NULL;
	}
	struct dialreq *req = pop_dialreq(L, n);
	lua_settop(L, 0);
	return req;
}

struct dialreq *ruleset_resolve(struct ruleset *r, const char *addr_str)
{
	return ruleset_call(r, "resolve", addr_str);
}

struct dialreq *ruleset_route(struct ruleset *r, const char *addr_str)
{
	return ruleset_call(r, "route", addr_str);
}

struct dialreq *ruleset_route6(struct ruleset *r, const char *addr_str)
{
	return ruleset_call(r, "route6", addr_str);
}
