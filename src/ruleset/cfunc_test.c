/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "dialer.h"
#include "io/stream.h"
#include "ruleset.h"

#include "ruleset/base.h"
#include "ruleset/cfunc.h"

#include "lauxlib.h"
#include "lua.h"
#include "utils/testing.h"

#include <arpa/inet.h>
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ev_tstamp TEST_WAIT_SEC = 0.128;

struct test_watchdog {
	bool fired;
};

struct string_stream {
	struct stream stream;
	const char *text;
	size_t len;
	bool consumed;
};

struct request_result {
	bool fired;
	struct dialreq *req;
	struct ruleset_callback *callback;
};

struct rpcall_result {
	bool fired;
	const char *result;
	size_t resultlen;
	struct ruleset_callback *callback;
};

static struct dialreq *g_last_req;
static size_t g_num_proxy_added;

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		if (predicate(data)) {
			ev_timer_stop(loop, &w_timeout);
			return true;
		}
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static bool request_fired(void *data)
{
	const struct request_result *const result = data;

	return result->fired;
}

static bool rpcall_fired(void *data)
{
	const struct rpcall_result *const result = data;

	return result->fired;
}

static int string_stream_direct_read(void *data, const void **buf, size_t *len)
{
	struct string_stream *const s = data;

	if (s->consumed) {
		*buf = NULL;
		*len = 0;
		return 0;
	}
	s->consumed = true;
	*buf = s->text;
	*len = s->len;
	return 0;
}

static const struct stream_vftable string_stream_vftable = {
	.direct_read = string_stream_direct_read,
};

static struct stream *
string_stream_open(struct string_stream *restrict s, const char *restrict text)
{
	*s = (struct string_stream){
		.stream = {
			.vftable = &string_stream_vftable,
			.data = s,
		},
		.text = text,
		.len = strlen(text),
		.consumed = false,
	};
	return &s->stream;
}

static int write_tempfile(char *restrict tmpl, const char *restrict content)
{
	const int fd = mkstemp(tmpl);
	const size_t len = strlen(content);

	if (fd < 0) {
		return -1;
	}
	if ((size_t)write(fd, content, len) != len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	return close(fd);
}

static struct config make_conf(void)
{
	return (struct config){
		.listen = "127.0.0.1:1080",
		.resolve_pf = PF_UNSPEC,
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
		.traceback = false,
		.memlimit = 0,
	};
}

static int stub_marshal_open(lua_State *restrict L)
{
	const char *restrict chunk =
		"return function(...) "
		"local out = {} "
		"for i = 1, select('#', ...) do "
		"  local v = select(i, ...) "
		"  local t = type(v) "
		"  if t == 'string' then "
		"    out[#out + 1] = string.format('%q', v) "
		"  elseif t == 'number' or t == 'boolean' then "
		"    out[#out + 1] = tostring(v) "
		"  elseif t == 'nil' then "
		"    out[#out + 1] = 'nil' "
		"  else "
		"    error('unsupported') "
		"  end "
		"end "
		"return table.concat(out, ',') "
		"end";

	T_CHECK(luaL_loadstring(L, chunk) == LUA_OK);
	lua_call(L, 0, 1);
	return 1;
}

int luaopen_await(lua_State *restrict L)
{
	lua_newtable(L);
	return 1;
}

int luaopen_marshal(lua_State *restrict L)
{
	return stub_marshal_open(L);
}

int luaopen_neosocksd(lua_State *restrict L)
{
	lua_newtable(L);
	return 1;
}

int luaopen_regex(lua_State *restrict L)
{
	lua_newtable(L);
	return 1;
}

int luaopen_time(lua_State *restrict L)
{
	lua_newtable(L);
	return 1;
}

int luaopen_zlib(lua_State *restrict L)
{
	lua_newtable(L);
	return 1;
}

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

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

struct dialreq *
dialreq_new(const struct dialreq *restrict base, const size_t num_proxy)
{
	const size_t size = sizeof(struct dialreq) +
			    num_proxy * sizeof(((struct dialreq *)0)->proxy[0]);
	struct dialreq *const req = calloc(1, size);

	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = num_proxy;
	g_last_req = req;
	g_num_proxy_added = 0;
	if (base != NULL) {
		req->addr = base->addr;
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

	if (req == NULL || g_num_proxy_added >= req->num_proxy ||
	    urilen >= sizeof(buf)) {
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
	proxy = &req->proxy[g_num_proxy_added++];
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

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	return parse_hostport(addr, s, len);
}

void dialreq_free(struct dialreq *req)
{
	if (g_last_req == req) {
		g_last_req = NULL;
		g_num_proxy_added = 0;
	}
	free(req);
}

static void
request_finish_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	struct request_result *const result = watcher->data;

	(void)revents;
	result->req = result->callback->request.req;
	result->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void
rpcall_finish_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	struct rpcall_result *const result = watcher->data;

	(void)revents;
	result->result = result->callback->rpcall.result;
	result->resultlen = result->callback->rpcall.resultlen;
	result->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static struct ruleset *
new_ruleset(struct ev_loop **restrict loop_out, struct config *restrict conf)
{
	struct ev_loop *const loop = ev_loop_new(0);
	struct ruleset *const r = ruleset_new(loop, conf, NULL, NULL);

	T_CHECK(loop != NULL);
	T_CHECK(r != NULL);
	*loop_out = loop;
	return r;
}

static void free_ruleset(struct ev_loop *loop, struct ruleset *restrict r)
{
	ruleset_free(r);
	ev_loop_destroy(loop);
}

static bool
install_ruleset(struct ruleset *restrict r, const char *restrict chunk)
{
	struct string_stream stream;

	return ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, NULL,
		string_stream_open(&stream, chunk));
}

static void seed_global_module(lua_State *restrict L, const char *restrict name)
{
	lua_newtable(L);
	lua_pushinteger(L, 1);
	lua_setfield(L, -2, "value");
	lua_pushvalue(L, -1);
	lua_setglobal(L, name);
	luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED");
	lua_pushvalue(L, -2);
	lua_setfield(L, -2, name);
	lua_pop(L, 2);
}

T_DECLARE_CASE(cfunc_loadfile_stats_tick_and_invoke_are_sandboxed)
{
	static const char file_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) return request end "
		"function ruleset.route6(request, username, password) return request end "
		"function ruleset.stats(dt, query) return string.format('%s:%s', modname, query or '') end "
		"function ruleset.tick() _G.tick_calls = (_G.tick_calls or 0) + 1 end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	char path[] = "/tmp/cfunc_test_XXXXXX";
	struct string_stream invoke_stream;
	double dt = 0.5;
	size_t len;
	const char *s;

	T_CHECK(write_tempfile(path, file_chunk) == 0);
	T_EXPECT(ruleset_pcall(r, cfunc_loadfile, 1, 0, path));

	T_EXPECT(ruleset_pcall(r, cfunc_stats, 2, 1, &dt, "alpha"));
	s = lua_tolstring(r->L, -1, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("ruleset:alpha"));
	T_EXPECT_MEMEQ(s, "ruleset:alpha", len);
	lua_pop(r->L, 1);

	T_EXPECT(ruleset_pcall(r, cfunc_tick, 0, 0));
	lua_getglobal(r->L, "tick_calls");
	T_EXPECT_EQ(lua_tointeger(r->L, -1), 1);
	lua_pop(r->L, 1);

	T_EXPECT(ruleset_pcall(
		r, cfunc_invoke, 1, 0,
		string_stream_open(
			&invoke_stream, "shadow = 1; local hidden = 2")));
	lua_getglobal(r->L, "shadow");
	T_EXPECT(lua_isnil(r->L, -1));
	lua_pop(r->L, 1);

	T_EXPECT(ruleset_pcall(r, cfunc_gc, 0, 0));
	(void)unlink(path);
	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_metrics_returns_string_when_defined_and_nil_when_absent)
{
	static const char with_metrics_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) return request end "
		"function ruleset.route6(request, username, password) return request end "
		"function ruleset.stats(dt, query) return '' end "
		"function ruleset.tick() end "
		"function ruleset.metrics() return 'custom_metric 1\\n' end "
		"return ruleset";
	static const char without_metrics_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) return request end "
		"function ruleset.route6(request, username, password) return request end "
		"function ruleset.stats(dt, query) return '' end "
		"function ruleset.tick() end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	size_t len;
	const char *s;

	/* with ruleset.metrics defined: returns the string */
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, with_metrics_chunk)));
	T_EXPECT(ruleset_pcall(r, cfunc_metrics, 0, 1));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	s = lua_tolstring(r->L, -1, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("custom_metric 1\n"));
	T_EXPECT_MEMEQ(s, "custom_metric 1\n", len);
	lua_pop(r->L, 1);

	/* without ruleset.metrics defined: stack has nil (nresults=1 pads) */
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, without_metrics_chunk)));
	T_EXPECT(ruleset_pcall(r, cfunc_metrics, 0, 1));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	T_EXPECT(lua_isnil(r->L, -1));
	lua_pop(r->L, 1);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_update_replaces_loaded_module)
{
	static const char mod_chunk[] =
		"local modname = ... "
		"return { value = 42, modname = modname }";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	seed_global_module(r->L, "demo");
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, "demo", "=(demo)",
		string_stream_open(&stream, mod_chunk)));

	lua_getglobal(r->L, "demo");
	T_CHECK(lua_istable(r->L, -1));
	lua_getfield(r->L, -1, "value");
	T_EXPECT_EQ(lua_tointeger(r->L, -1), 42);
	lua_pop(r->L, 1);
	lua_getfield(r->L, -1, "modname");
	T_EXPECT_STREQ(lua_tostring(r->L, -1), "demo");
	lua_pop(r->L, 1);
	luaL_getsubtable(r->L, LUA_REGISTRYINDEX, "_LOADED");
	lua_getfield(r->L, -1, "demo");
	T_EXPECT(lua_rawequal(r->L, -1, -3));
	lua_pop(r->L, 3);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_request_accepts_and_rejects)
{
	static const char ruleset_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) "
		"  if username == 'allow' then return request end "
		"  return nil "
		"end "
		"function ruleset.route6(request, username, password) return request end "
		"function ruleset.stats(dt, query) return '' end "
		"function ruleset.tick() end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(install_ruleset(r, ruleset_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 6, 1, &state, "route", "127.0.0.1:80",
		"allow", "pw", &cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 6, 1, &state, "route", "127.0.0.1:80", "deny",
		"pw", &cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_request_reports_lua_error_via_callback)
{
	static const char ruleset_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) error('route boom') end "
		"function ruleset.route6(request, username, password) return request end "
		"function ruleset.stats(dt, query) return '' end "
		"function ruleset.tick() end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(install_ruleset(r, ruleset_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 6, 1, &state, "route", "127.0.0.1:80", NULL,
		NULL, &cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT_STREQ(ruleset_geterror(r, NULL), "(nil)");

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_rpcall_marshals_results_and_keeps_env_local)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct rpcall_result result = {
		.callback = &cb,
	};

	ev_init(&cb.w_finish, rpcall_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_pcall(
		r, cfunc_rpcall, 3, 1, &state,
		string_stream_open(&stream, "shadow = 1; return 7, 'ok', false"),
		&cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, rpcall_fired, &result, TEST_WAIT_SEC));
	T_EXPECT(result.result != NULL);
	T_EXPECT(strstr(result.result, "return ") == result.result);
	T_EXPECT(strstr(result.result, "7") != NULL);
	T_EXPECT(strstr(result.result, "ok") != NULL);
	T_EXPECT(strstr(result.result, "false") != NULL);

	lua_getglobal(r->L, "shadow");
	T_EXPECT(lua_isnil(r->L, -1));
	lua_pop(r->L, 1);

	free_ruleset(loop, r);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, cfunc_loadfile_stats_tick_and_invoke_are_sandboxed);
	T_RUN_CASE(
		t,
		cfunc_metrics_returns_string_when_defined_and_nil_when_absent);
	T_RUN_CASE(t, cfunc_update_replaces_loaded_module);
	T_RUN_CASE(t, cfunc_request_accepts_and_rejects);
	T_RUN_CASE(t, cfunc_request_reports_lua_error_via_callback);
	T_RUN_CASE(t, cfunc_rpcall_marshals_results_and_keeps_env_local);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
