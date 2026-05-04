/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/api.h"

#include "ruleset/base.h"

#include "api_client.h"
#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "server.h"
#include "util.h"

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "utils/testing.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static struct {
	bool invoke_called;
	struct dialreq *req;
	char payload[256];
	size_t payload_len;
	const struct config *conf;
	struct resolver *resolver;
	struct server_stats stats;
	struct resolver_stats resolver_stats;
} G = {
	.invoke_called = false,
	.req = NULL,
	.payload = { 0 },
	.payload_len = 0,
	.conf = NULL,
	.resolver = NULL,
	.stats = { 0 },
	.resolver_stats = {
		.num_query = 7,
		.num_success = 5,
	},
};

static void reset_globals(void)
{
	if (G.req != NULL) {
		dialreq_free(G.req);
		G.req = NULL;
	}
	G.invoke_called = false;
	G.payload[0] = '\0';
	G.payload_len = 0;
	G.conf = NULL;
	G.resolver = NULL;
	G.stats = (struct server_stats){ 0 };
	G.resolver_stats = (struct resolver_stats){
		.num_query = 7,
		.num_success = 5,
	};
}

static void
dummy_timer_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
}

static void
dummy_idle_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
}

static bool parse_hostport(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	char buf[256];
	char *host = buf;
	char *port = NULL;

	if (len >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, s, len);
	buf[len] = '\0';
	if (buf[0] == '[') {
		char *end = strchr(buf, ']');
		if (end == NULL || end[1] != ':') {
			return false;
		}
		*end = '\0';
		host = buf + 1;
		port = end + 2;
	} else {
		port = strrchr(buf, ':');
		if (port == NULL) {
			return false;
		}
		*port++ = '\0';
	}
	addr->port = (uint_least16_t)strtoul(port, NULL, 10);
	if (inet_pton(AF_INET, host, &addr->in) == 1) {
		addr->type = ATYP_INET;
		return true;
	}
	if (inet_pton(AF_INET6, host, &addr->in6) == 1) {
		addr->type = ATYP_INET6;
		return true;
	}
	addr->type = ATYP_DOMAIN;
	addr->domain.len = (uint_least8_t)strlen(host);
	memcpy(addr->domain.name, host, addr->domain.len);
	return true;
}

/*
 * api.c and base.c are included as sources.  The stubs below satisfy their
 * external dependencies that are outside the scope of these tests.  The
 * tested functions (parse_ipv4, parse_ipv6, splithostport, traceback) do
 * not access a live ruleset, so aux_getruleset returning NULL is fine.
 */

/* ---- dialer stubs (required by base.c's aux_todialreq) ---- */

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	const size_t base_num_proxy = (base != NULL) ? base->num_proxy : 0;
	struct dialreq *const req =
		calloc(1, sizeof(*req) + (base_num_proxy + num_proxy) *
						 sizeof(req->proxy[0]));

	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = base_num_proxy;
	if (base != NULL) {
		req->addr = base->addr;
		memcpy(req->proxy, base->proxy,
		       base_num_proxy * sizeof(req->proxy[0]));
	}
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	char buf[256];
	char *scheme;
	char *hostport;
	struct proxyreq *proxy;

	if (req == NULL || urilen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, proxy_uri, urilen);
	buf[urilen] = '\0';
	scheme = buf;
	hostport = strstr(buf, "://");
	if (hostport == NULL) {
		return false;
	}
	*hostport = '\0';
	hostport += 3;
	proxy = &req->proxy[req->num_proxy++];
	if (strcmp(scheme, "http") == 0) {
		proxy->proto = PROTO_HTTP;
	} else if (strcmp(scheme, "socks4a") == 0) {
		proxy->proto = PROTO_SOCKS4A;
	} else if (strcmp(scheme, "socks5") == 0) {
		proxy->proto = PROTO_SOCKS5;
	} else {
		return false;
	}
	return parse_hostport(&proxy->addr, hostport, strlen(hostport));
}

void dialreq_free(struct dialreq *req)
{
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	return parse_hostport(addr, s, len);
}

/* ---- resolver stub (required by api.c's api_stats) ---- */

const struct resolver_stats *resolver_stats(const struct resolver *restrict r)
{
	(void)r;
	return &G.resolver_stats;
}

/* ---- server stub (required by api.c's api_stats) ---- */

void server_stats(
	const struct server *restrict s, struct server_stats *restrict out)
{
	(void)s;
	*out = G.stats;
}

/* ---- api_client stub (required by api.c's api_invoke) ---- */

void api_client_invoke(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const void *restrict payload, const size_t len,
	const struct config *restrict conf, struct resolver *restrict resolver)
{
	(void)loop;
	G.invoke_called = true;
	G.req = req;
	G.payload_len =
		len < sizeof(G.payload) - 1 ? len : sizeof(G.payload) - 1;
	memcpy(G.payload, payload, G.payload_len);
	G.payload[G.payload_len] = '\0';
	G.conf = conf;
	G.resolver = resolver;
}

/* ---- util stub (required by util.c's loadlibs if ever called) ---- */

const char *neosocksd_version(void)
{
	return "test";
}

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	(void)s;
	(void)maxlen;
	(void)r;
	return -1;
}

void resolver_init(void)
{
}
void resolver_cleanup(void)
{
}

/* ---- Lua helpers ---- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_neosocksd(L);
	lua_setglobal(L, "neosocksd");
	return L;
}

static lua_State *new_ruleset_lua(
	struct ruleset *restrict r, struct config *restrict conf,
	struct ev_loop *loop)
{
	lua_State *restrict L = luaL_newstate();
	lua_Alloc alloc;

	T_CHECK(L != NULL);
	alloc = lua_getallocf(L, NULL);
	lua_setallocf(L, alloc, r);
	luaL_openlibs(L);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	aux_newweaktable(L, "k");
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_IDLE_THREAD);
	r->loop = loop;
	r->conf = conf;
	r->resolver = (struct resolver *)0x1234;
	r->server = NULL;
	r->basereq = NULL;
	r->L = L;
	r->config.traceback = false;
	r->config.memlimit_kb = 0;
	r->vmstats = (struct ruleset_vmstats){
		.num_object = 33,
		.byt_allocated = 4096,
	};
	ev_timer_init(&r->w_ticker, dummy_timer_cb, 1.0, 1.0);
	ev_idle_init(&r->w_idle, dummy_idle_cb);
	(void)luaopen_neosocksd(L);
	lua_setglobal(L, "neosocksd");
	return L;
}

static bool run_chunk(lua_State *restrict L, const char *restrict chunk)
{
	if (luaL_loadstring(L, chunk) != LUA_OK) {
		return false;
	}
	return lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK;
}

/* ---- tests ---- */

T_DECLARE_CASE(api_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "neosocksd");
	T_EXPECT(lua_istable(L, -1));

	const char *const fns[] = {
		"async",	 "config",     "invoke",    "now",
		"parse_ipv4",	 "parse_ipv6", "resolve",   "setinterval",
		"splithostport", "stats",      "traceback",
	};
	for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
		lua_getfield(L, -1, fns[i]);
		T_EXPECT(lua_isfunction(L, -1));
		lua_pop(L, 1);
	}

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv4_valid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return neosocksd.parse_ipv4('127.0.0.1')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0x7f000001);

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv4_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* each of these should return zero values */
	T_EXPECT(run_chunk(
		L, "local a = neosocksd.parse_ipv4('999.0.0.1') "
		   "local b = neosocksd.parse_ipv4('abc') "
		   "local c = neosocksd.parse_ipv4(nil) "
		   "return a, b, c"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT(lua_isnil(L, 1));
	T_EXPECT(lua_isnil(L, 2));
	T_EXPECT(lua_isnil(L, 3));

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv6_valid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* "::1" -> all-zeros high half, 1 in low half */
	T_EXPECT(run_chunk(L, "return neosocksd.parse_ipv6('::1')"));
#if LUA_32BITS
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 2), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 3), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 4), (lua_Integer)1);
#else
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), (lua_Integer)0);
	T_EXPECT_EQ(lua_tointeger(L, 2), (lua_Integer)1);
#endif

	lua_close(L);
}

T_DECLARE_CASE(api_parse_ipv6_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local a = neosocksd.parse_ipv6('::g') "
		   "local b = neosocksd.parse_ipv6(nil) "
		   "return a, b"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_isnil(L, 1));
	T_EXPECT(lua_isnil(L, 2));

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_simple)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "return neosocksd.splithostport('example.com:80')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_STREQ(lua_tostring(L, 1), "example.com");
	T_EXPECT_STREQ(lua_tostring(L, 2), "80");

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_ipv6)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return neosocksd.splithostport('[::1]:443')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_STREQ(lua_tostring(L, 1), "::1");
	T_EXPECT_STREQ(lua_tostring(L, 2), "443");

	lua_close(L);
}

T_DECLARE_CASE(api_splithostport_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* missing port – must raise a Lua error caught by pcall */
	const int rc_load = luaL_loadstring(
		L, "local ok, err = pcall(neosocksd.splithostport, 'noport') "
		   "return ok, err");
	T_EXPECT_EQ(rc_load, LUA_OK);
	const int rc_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(rc_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT(lua_type(L, 2) == LUA_TSTRING);

	lua_close(L);
}

T_DECLARE_CASE(api_traceback_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(L, "return neosocksd.traceback('boom')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	const char *restrict s = lua_tostring(L, -1);
	T_CHECK(s != NULL);
	T_EXPECT(strstr(s, "boom") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(api_config_reflects_ruleset_conf)
{
	struct config conf = {
		.listen = "127.0.0.1:1080",
		.forward = "127.0.0.1:8080",
		.timeout = 12.5,
		.traceback = true,
		.memlimit = 64,
		.auth_required = true,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_globals();
	T_EXPECT(run_chunk(
		L,
		"local c = neosocksd.config() "
		"return c.listen, c.forward, c.timeout, c.traceback, c.memlimit, c.auth_required"));
	T_EXPECT_STREQ(lua_tostring(L, 1), "127.0.0.1:1080");
	T_EXPECT_STREQ(lua_tostring(L, 2), "127.0.0.1:8080");
	T_EXPECT_EQ(lua_tonumber(L, 3), 12.5);
	T_EXPECT(lua_toboolean(L, 4) != 0);
	T_EXPECT_EQ(lua_tointeger(L, 5), 64);
	T_EXPECT(lua_toboolean(L, 6) != 0);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(api_stats_now_and_setinterval_use_ruleset_state)
{
	struct config conf = {
		.listen = "127.0.0.1:1080",
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
	struct ruleset r = { 0 };
	struct server server = {
		.resolver = (struct resolver *)0x1234,
	};
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_globals();
	r.server = &server;
	G.stats = (struct server_stats){
		.num_sessions = 3,
		.byt_up = 11,
		.byt_down = 22,
	};
	ev_now_update(loop);

	T_EXPECT(run_chunk(
		L,
		"local s = neosocksd.stats() "
		"return s.num_sessions, s.num_dns_query, s.num_dns_success, s.bytes_allocated, s.num_object, neosocksd.now()"));
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_EQ(lua_tointeger(L, 2), 7);
	T_EXPECT_EQ(lua_tointeger(L, 3), 5);
	T_EXPECT_EQ(lua_tointeger(L, 4), 4096);
	T_EXPECT_EQ(lua_tointeger(L, 5), 33);
	T_EXPECT(lua_tonumber(L, 6) > 0.0);

	T_EXPECT(run_chunk(L, "return neosocksd.setinterval(-1)"));
	T_EXPECT(ev_is_active(&r.w_idle));
	T_EXPECT_EQ(r.w_ticker.repeat, 0.0);
	T_EXPECT(run_chunk(L, "return neosocksd.setinterval(0.25)"));
	T_EXPECT(ev_is_active(&r.w_ticker));
	T_EXPECT_EQ(r.w_ticker.repeat, 0.25);

	lua_close(L);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(api_invoke_and_async_real_paths)
{
	struct config conf = {
		.listen = "127.0.0.1:1080",
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
	struct ruleset r = { 0 };
	struct ev_loop *const loop = ev_loop_new(0);
	lua_State *restrict L = new_ruleset_lua(&r, &conf, loop);

	reset_globals();
	T_EXPECT(run_chunk(
		L,
		"neosocksd.invoke('return 1', '127.0.0.1:80') "
		"local co, err = neosocksd.async(function(ok, value) _G.async_ok = ok; _G.async_value = value end, function() return 7 end) "
		"return co ~= nil, err == nil, _G.async_ok, _G.async_value"));
	T_EXPECT(G.invoke_called);
	T_CHECK(G.req != NULL);
	T_EXPECT_STREQ(G.payload, "return 1");
	T_EXPECT_EQ(G.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(G.req->addr.port, UINT16_C(80));
	T_EXPECT_EQ(G.conf, &conf);
	T_EXPECT_EQ(G.resolver, r.resolver);
	T_EXPECT(lua_toboolean(L, 1) != 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);
	T_EXPECT(lua_toboolean(L, 3) != 0);
	T_EXPECT_EQ(lua_tointeger(L, 4), 7);

	lua_close(L);
	ev_loop_destroy(loop);
	reset_globals();
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, api_module_opens);
	T_RUN_CASE(t, api_parse_ipv4_valid);
	T_RUN_CASE(t, api_parse_ipv4_invalid);
	T_RUN_CASE(t, api_parse_ipv6_valid);
	T_RUN_CASE(t, api_parse_ipv6_invalid);
	T_RUN_CASE(t, api_splithostport_simple);
	T_RUN_CASE(t, api_splithostport_ipv6);
	T_RUN_CASE(t, api_splithostport_invalid);
	T_RUN_CASE(t, api_traceback_string);
	T_RUN_CASE(t, api_config_reflects_ruleset_conf);
	T_RUN_CASE(t, api_stats_now_and_setinterval_use_ruleset_state);
	T_RUN_CASE(t, api_invoke_and_async_real_paths);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
