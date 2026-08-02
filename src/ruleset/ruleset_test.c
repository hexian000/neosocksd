/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * ruleset_test - white-box unit tests for ruleset.c and ruleset/cfunc.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset.c        module under test
 *   ruleset/cfunc.c  module under test (sandboxed C-function dispatch)
 *   ruleset/base.c   ruleset Lua substrate
 *   conf.c           config data
 *   proto/codec.c    leaf
 *   version.c        leaf
 * The luaopen_* module entry points are replaced by the mocks in the mock
 * section below.
 */

#include "ruleset/ruleset.h"

#include "conf.h"
#include "dialer.h"
#include "proto/codec.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
#include "server.h"

#include "io/stream.h"
#include "utils/testing.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - luaopen_* stubs and shared fixtures.
 * ---------------------------------------------------------------------- */

static const ev_tstamp TEST_WAIT_SEC = 0.128;

struct test_watchdog {
	bool fired;
};

struct string_stream {
	struct io_stream stream;
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

static const struct io_stream_vftable string_stream_vftable = {
	.direct_read = string_stream_direct_read,
};

static struct io_stream *
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
#if WITH_RULESET
		.traceback = false,
		.memlimit = 0,
#endif
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

const char *const proxy_protocol_str[PROTO_MAX] = {
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

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - ruleset load/update/dispatch lifecycle cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(ruleset_loadfile_dispatches_requests)
{
	static const char script[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.stats(dt, query) return query or '' end "
		"  function ruleset.tick() end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	char path[] = "/tmp/ruleset_test_XXXXXX";
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_CHECK(write_tempfile(path, script) == 0);
	T_EXPECT(ruleset_loadfile(r, path));

	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_resolve(
		r, &state, "example.com:443", "alice", "secret", &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(443));
	T_EXPECT_EQ(result.req->addr.domain.len, strlen("example.com"));
	T_EXPECT_MEMEQ(
		result.req->addr.domain.name, "example.com",
		result.req->addr.domain.len);
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(80));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_route6(r, &state, "[::1]:53", NULL, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET6);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(53));
	dialreq_free(result.req);

	ruleset_setserver(r, (struct server *)0x1);
	T_EXPECT(r->server == (struct server *)0x1);
	(void)unlink(path);
	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_dispatch_routes_by_address_type)
{
	/* Each entry point returns a distinct self-identifying address, so a
	 * mis-mapped ruleset_dispatch arm yields the wrong parsed type/port. */
	static const char script[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.resolve() return 'resolve.example:1' end "
		"  function ruleset.route() return '192.0.2.1:2' end "
		"  function ruleset.route6() return '[2001:db8::1]:3' end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	char path[] = "/tmp/ruleset_test_XXXXXX";
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_CHECK(write_tempfile(path, script) == 0);
	T_EXPECT(ruleset_loadfile(r, path));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;

	T_EXPECT(ruleset_dispatch(
		r, &state, "example.org:0", ATYP_DOMAIN, NULL, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(1));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_dispatch(
		r, &state, "203.0.113.1:0", ATYP_INET, NULL, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(2));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_dispatch(
		r, &state, "[2001:db8::9]:0", ATYP_INET6, NULL, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET6);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(3));
	dialreq_free(result.req);

	(void)unlink(path);
	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_update_invoke_rpcall_stats_and_tick)
{
	static const char update_chunk[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route(request, username, password) "
		"    return '127.0.0.1:7001' "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return '[::1]:7002' "
		"  end "
		"  function ruleset.stats(dt, query) "
		"    return string.format('ticks=%d;query=%s;dt=%.1f', _G.tick_count or 0, query or '', dt) "
		"  end "
		"  function ruleset.tick() _G.tick_count = (_G.tick_count or 0) + 1 end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream update_stream;
	struct string_stream invoke_stream;
	struct string_stream error_stream;
	struct string_stream rpc_stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct rpcall_result rpc_result = {
		.callback = &cb,
	};
	struct ruleset_vmstats stats = { 0 };
	size_t len = 0;
	const char *s;

	T_EXPECT(ruleset_update(
		r, NULL, NULL,
		string_stream_open(&update_stream, update_chunk)));
	T_EXPECT(ruleset_invoke(
		r, string_stream_open(
			   &invoke_stream,
			   "local sum = 20 + 22 assert(sum == 42)")));
	T_EXPECT(!ruleset_invoke(
		r, string_stream_open(&error_stream, "error('invoke boom')")));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "invoke boom") != NULL);

	ev_init(&cb.w_finish, rpcall_finish_cb);
	cb.w_finish.data = &rpc_result;
	T_EXPECT(ruleset_rpcall(
		r, &state, string_stream_open(&rpc_stream, "return 42, 'done'"),
		&cb));
	T_EXPECT(wait_until(loop, rpcall_fired, &rpc_result, TEST_WAIT_SEC));
	T_EXPECT(rpc_result.result != NULL);
	/* the result buffer holds exactly resultlen bytes with no NUL terminator,
	 * so copy into a terminated local before letting strstr scan it */
	char rbuf[256];
	T_CHECK(rpc_result.resultlen < sizeof(rbuf));
	memcpy(rbuf, rpc_result.result, rpc_result.resultlen);
	rbuf[rpc_result.resultlen] = '\0';
	T_EXPECT(strstr(rbuf, "return ") == rbuf);
	T_EXPECT(strstr(rbuf, "42") != NULL);
	T_EXPECT(strstr(rbuf, "done") != NULL);
	free((void *)rpc_result.result);

	s = ruleset_stats(r, 1.5, "alpha", &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("ticks=0;query=alpha;dt=1.5"));
	T_EXPECT_MEMEQ(s, "ticks=0;query=alpha;dt=1.5", len);

	ev_invoke(loop, &r->w_ticker, EV_TIMER);
	ev_invoke(loop, &r->w_idle, EV_IDLE);
	s = ruleset_stats(r, 2.0, "beta", &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("ticks=1;query=beta;dt=2.0"));
	T_EXPECT_MEMEQ(s, "ticks=1;query=beta;dt=2.0", len);

	T_EXPECT(ruleset_gc(r));
	ruleset_vmstats(r, &stats);
	T_EXPECT(stats.num_events > 0);
	T_EXPECT_EQ(stats.num_thread_active, (size_t)0);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_metrics_returns_string_when_defined_and_null_when_absent)
{
	static const char with_metrics_chunk[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.stats(dt, query) return '' end "
		"  function ruleset.tick() end "
		"  function ruleset.metrics() return 'custom_metric 42\\n' end "
		"  return ruleset "
		"";
	static const char without_metrics_chunk[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.stats(dt, query) return '' end "
		"  function ruleset.tick() end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	size_t len = 0;
	const char *s;

	T_EXPECT(ruleset_update(
		r, NULL, NULL,
		string_stream_open(&stream, with_metrics_chunk)));
	s = ruleset_metrics(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("custom_metric 42\n"));
	T_EXPECT_MEMEQ(s, "custom_metric 42\n", len);

	T_EXPECT(ruleset_update(
		r, NULL, NULL,
		string_stream_open(&stream, without_metrics_chunk)));
	s = ruleset_metrics(r, &len);
	T_EXPECT_EQ(s, NULL);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_healthy_reports_unhealthy_string_and_null_when_ok)
{
#define HEALTHY_PRELUDE                                                        \
	"local name = ... "                                                    \
	"  local ruleset = {} "                                                \
	"  function ruleset.resolve(request, username, password) "             \
	"    return request "                                                  \
	"  end "                                                               \
	"  function ruleset.route(request, username, password) "               \
	"    return request "                                                  \
	"  end "                                                               \
	"  function ruleset.route6(request, username, password) "              \
	"    return request "                                                  \
	"  end "                                                               \
	"  function ruleset.stats(dt, query) return '' end "                   \
	"  function ruleset.tick() end "
#define HEALTHY_CHUNK(body) HEALTHY_PRELUDE body "  return ruleset "
	static const char unhealthy_chunk[] = HEALTHY_CHUNK(
		"function ruleset.healthy() return 'down: db' end ");
	static const char empty_chunk[] =
		HEALTHY_CHUNK("function ruleset.healthy() return '' end ");
	static const char nil_chunk[] =
		HEALTHY_CHUNK("function ruleset.healthy() return nil end ");
	static const char error_chunk[] =
		HEALTHY_CHUNK("function ruleset.healthy() error('boom') end ");
	static const char without_chunk[] = HEALTHY_CHUNK("");
#undef HEALTHY_CHUNK
#undef HEALTHY_PRELUDE
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	size_t len = 0;
	const char *s;

	/* a non-empty string marks the service unhealthy */
	T_EXPECT(ruleset_update(
		r, NULL, NULL, string_stream_open(&stream, unhealthy_chunk)));
	s = ruleset_healthy(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("down: db"));
	T_EXPECT_MEMEQ(s, "down: db", len);

	/* an empty string means healthy */
	T_EXPECT(ruleset_update(
		r, NULL, NULL, string_stream_open(&stream, empty_chunk)));
	s = ruleset_healthy(r, &len);
	T_EXPECT_EQ(s, NULL);

	/* nil means healthy */
	T_EXPECT(ruleset_update(
		r, NULL, NULL, string_stream_open(&stream, nil_chunk)));
	s = ruleset_healthy(r, &len);
	T_EXPECT_EQ(s, NULL);

	/* an absent callback means healthy */
	T_EXPECT(ruleset_update(
		r, NULL, NULL, string_stream_open(&stream, without_chunk)));
	s = ruleset_healthy(r, &len);
	T_EXPECT_EQ(s, NULL);

	/* a callback that raises is reported as unhealthy */
	T_EXPECT(ruleset_update(
		r, NULL, NULL, string_stream_open(&stream, error_chunk)));
	s = ruleset_healthy(r, &len);
	T_CHECK(s != NULL);
	T_CHECK(strstr(s, "boom") != NULL);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_cancel_pending_request_clears_callback)
{
	static const char update_chunk[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.route(request, username, password) "
		"    coroutine.yield() "
		"  end "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.stats(dt, query) return '' end "
		"  function ruleset.tick() end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream update_stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(ruleset_update(
		r, NULL, NULL,
		string_stream_open(&update_stream, update_chunk)));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, NULL, &cb));
	T_CHECK(state != NULL);
	T_CHECK(state->cb == &cb);
	ruleset_cancel(loop, state);
	T_EXPECT_EQ(state->cb, NULL);
	/* ruleset_cancel is documented idempotent: a second call is a safe
	 * no-op (the state->cb == NULL guard) */
	ruleset_cancel(loop, state);
	T_EXPECT_EQ(state->cb, NULL);
	/* the callback is already cleared (asserted above), so it cannot fire --
	 * no wall-clock wait is needed to confirm the request never completes */

	free_ruleset(loop, r);
}

/*
 * Regression: ruleset_state must be detached from the caller's own storage
 * slot (here, the local `state`) synchronously when the routine completes,
 * not merely whenever the fed completion event happens to be dispatched.
 * Before the fix, `state` stayed non-NULL until the event was processed, so
 * a concurrent ruleset_cancel() racing with a GC cycle in that window could
 * be handed a dangling pointer -- reproduced upstream under
 * AddressSanitizer as a heap-use-after-free in ruleset_cancel().
 */
T_DECLARE_CASE(ruleset_state_detached_synchronously_on_completion)
{
	static const char update_chunk[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.route(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.resolve(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.route6(request, username, password) "
		"    return request "
		"  end "
		"  function ruleset.stats(dt, query) return '' end "
		"  function ruleset.tick() end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream update_stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(ruleset_update(
		r, NULL, NULL,
		string_stream_open(&update_stream, update_chunk)));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;

	/* ruleset.route above does not yield, so request_finish() (and thus
	 * state_complete()) runs synchronously inside this very call, before
	 * ruleset_route() returns -- well before the fed completion event is
	 * ever dispatched. */
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, NULL, &cb));
	T_EXPECT(state == NULL);

	/* Force a full GC cycle: with the fix, there is nothing left for any
	 * caller to dangle a pointer to; this must not crash (and would
	 * report a heap-use-after-free under AddressSanitizer without the
	 * fix, once combined with a stale ruleset_cancel() call). */
	lua_gc(r->L, LUA_GCCOLLECT, 0);

	/* The fed completion event must still be delivered normally. */
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	dialreq_free(result.req);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_geterror_variants)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	size_t len = 0;
	const char *err;

	err = ruleset_geterror(r, &len);
	T_EXPECT_EQ(len, strlen("(nil)"));
	T_EXPECT_MEMEQ(err, "(nil)", len);

	lua_pushstring(r->L, "sentinel");
	lua_rawseti(r->L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	err = ruleset_geterror(r, &len);
	T_EXPECT_EQ(len, strlen("sentinel"));
	T_EXPECT_MEMEQ(err, "sentinel", len);

	lua_pushboolean(r->L, 1);
	lua_rawseti(r->L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	err = ruleset_geterror(r, &len);
	T_EXPECT_EQ(len, strlen("(error object is not a string)"));
	T_EXPECT_MEMEQ(err, "(error object is not a string)", len);

	ruleset_free(NULL);
	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_isvalid_tracks_loaded_table)
{
	static const char script[] =
		"local name = ... "
		"  local ruleset = {} "
		"  function ruleset.route(request) return request end "
		"  return ruleset "
		"";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	char path[] = "/tmp/ruleset_test_XXXXXX";

	/* a fresh ruleset has no `ruleset' global yet */
	T_EXPECT(!ruleset_isvalid(r));

	T_CHECK(write_tempfile(path, script) == 0);
	T_EXPECT(ruleset_loadfile(r, path));
	/* after loading a table-returning script it is valid */
	T_EXPECT(ruleset_isvalid(r));

	(void)unlink(path);
	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_load_missing_file_returns_false)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);

	/* codec_lua_reader() returns NULL for a nonexistent path; both loaders
	 * must early-return false rather than crash, and record a "cannot open"
	 * error so ruleset_geterror does not report "(nil)" */
	T_EXPECT(!ruleset_loadfile(r, "/nonexistent/ruleset/path.lua"));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "cannot open") != NULL);
	T_EXPECT(!ruleset_loadconfig(r, "/nonexistent/ruleset/config.lua"));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "cannot open") != NULL);

	free_ruleset(loop, r);
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
	struct io_stream *restrict code = codec_lua_reader(path);
	T_CHECK(code != NULL);
	T_EXPECT(ruleset_pcall(r, cfunc_loadfile, 1, 0, code));
	io_stream_close(code);

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
	/* rpcall_finish marshals every value including the leading ok=true flag
	 * (unlike request_finish, which drops it via lua_gettop(L)-1). Pin the
	 * exact payload: a regression to lua_gettop(L)-1 would silently drop the
	 * leading true that libruleset await.rpcall consumes as its success
	 * flag, and substring checks alone would still pass. */
	static const char expect[] = "return true,7,\"ok\",false";
	T_CHECK(result.resultlen == sizeof(expect) - 1);
	T_EXPECT_MEMEQ(result.result, expect, sizeof(expect) - 1);
	free((void *)result.result);

	lua_getglobal(r->L, "shadow");
	T_EXPECT(lua_isnil(r->L, -1));
	lua_pop(r->L, 1);

	free_ruleset(loop, r);
}

/*
 * Regression: rpcall_finish() used to store a raw pointer into a Lua
 * string that lived only on the coroutine's stack. thread_call_k() pops
 * it via lua_settop() right after rpcall_finish() returns -- dropping the
 * sole reference -- while the deferred w_finish event reads the result
 * later; any Lua GC cycle in that window could collect the string out
 * from under the still-pending pointer. Force a full GC cycle right
 * after the event fires (standing in for an intervening Lua allocation
 * in production) to prove the result now survives it: it must be a
 * malloc()'d copy, not a borrowed reference into Lua-owned memory.
 */
T_DECLARE_CASE(cfunc_rpcall_result_survives_gc_before_read)
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
		string_stream_open(&stream, "return string.rep('x', 1000)"),
		&cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, rpcall_fired, &result, TEST_WAIT_SEC));
	T_EXPECT(result.result != NULL);

	/* If result.result still borrowed Lua-owned memory, this collects it
	 * out from under the pointer; ASan would catch the reads below as a
	 * use-after-free. */
	lua_gc(r->L, LUA_GCCOLLECT, 0);

	/* the leading ok=true flag must survive too (see the pinned-shape test
	 * above); assert the exact prefix rather than a bare "return " */
	static const char prefix[] = "return true,\"";
	T_CHECK(result.resultlen >= sizeof(prefix) - 1);
	T_EXPECT_MEMEQ(result.result, prefix, sizeof(prefix) - 1);
	size_t x_count = 0;
	for (size_t i = 0; i < result.resultlen; i++) {
		if (result.result[i] == 'x') {
			x_count++;
		}
	}
	T_EXPECT_EQ(x_count, 1000);
	free((void *)result.result);

	free_ruleset(loop, r);
}

/*
 * Regression: an rpcall whose return value fails to marshal (e.g. a
 * function, which marshal() does not support) must still complete the
 * caller's callback with an error result -- not silently drop it. Before
 * the fix, marshal()'s error propagated straight out of rpcall_finish via
 * lua_call(), skipping state_complete() entirely; the caller would then
 * hang until an unrelated GC eventually collected the orphaned state.
 */
T_DECLARE_CASE(cfunc_rpcall_unmarshalable_result_reports_error)
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
		string_stream_open(&stream, "return function() end"), &cb));
	lua_pop(r->L, 1);
	/* Must complete within the short timeout, not hang. */
	T_EXPECT(wait_until(loop, rpcall_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.result, NULL);
	T_EXPECT_EQ(result.resultlen, 0);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_rpcall_chunk_error_reports_failure)
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
	/* a chunk that raises must surface as an rpcall failure, not a
	 * marshalled (false, "boom") "successful" result */
	T_EXPECT(ruleset_pcall(
		r, cfunc_rpcall, 3, 1, &state,
		string_stream_open(&stream, "error('boom')"), &cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, rpcall_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.result, NULL);
	T_EXPECT_EQ(result.resultlen, 0);

	free_ruleset(loop, r);
}

/*
 * Regression: a client rpcall chunk with a syntax error makes lua_load()
 * raise before aux_async() runs. The coroutine must be checked out only
 * after that, so num_thread_active stays balanced -- otherwise a client
 * submitting malformed code repeatedly inflates the gauge without bound and
 * drops a coroutine from the idle pool on every attempt.
 */
T_DECLARE_CASE(cfunc_rpcall_syntax_error_does_not_leak_thread)
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
	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);
	/* "return (" fails to compile: cfunc_rpcall must raise (pcall reports
	 * failure) without having checked out a coroutine */
	T_EXPECT(!ruleset_pcall(
		r, cfunc_rpcall, 3, 1, &state,
		string_stream_open(&stream, "return ("), &cb));
	T_EXPECT_EQ(r->vmstats.num_thread_active, 0);
	/* the callback must never fire for a chunk that did not load */
	T_EXPECT(!result.fired);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_request_malformed_dial_spec_is_rejected)
{
	static const char ruleset_chunk[] =
		"local ruleset = {} "
		"function ruleset.resolve(request, username, password) return request end "
		"function ruleset.route(request, username, password) return 'bogus' end "
		"function ruleset.route6(request, username, password) return request end "
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
	/* route() returns an address aux_todialreq cannot parse: the request
	 * must degrade to "rejected" (req == NULL) rather than misbehave */
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 6, 1, &state, "route", "127.0.0.1:80", NULL,
		NULL, &cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_loadconfig_extracts_ruleset_and_settings)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(
			&stream,
			"return { ruleset = { tag = 1 }, memlimit = 4, traceback = true }")));
	/* the `ruleset' table is promoted to the global and removed from the
	 * config table; memlimit (MiB) and traceback land in r->config */
	lua_getglobal(r->L, "ruleset");
	T_EXPECT(lua_istable(r->L, -1));
	lua_pop(r->L, 1);
	T_EXPECT_EQ(r->config.memlimit_kb, (int_least32_t)(4 << 10));
	T_EXPECT(r->config.traceback);

	free_ruleset(loop, r);
	free(conf.strings);
}

T_DECLARE_CASE(cfunc_loadconfig_rejects_non_table)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(&stream, "return 42")));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "expected table") != NULL);

	free_ruleset(loop, r);
	free(conf.strings);
}

/* Regression: cfunc_loadfile must reject a chunk that returns a non-table
 * rather than installing a broken global ruleset (like cfunc_loadconfig). */
T_DECLARE_CASE(cfunc_loadfile_rejects_non_table)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadfile, 1, 0,
		string_stream_open(&stream, "return 42")));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "expected table") != NULL);

	free_ruleset(loop, r);
	free(conf.strings);
}

T_DECLARE_CASE(cfunc_loadconfig_rejects_wrong_type_ruleset)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(&stream, "return { ruleset = 5 }")));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "must be a table") != NULL);

	free_ruleset(loop, r);
	free(conf.strings);
}

T_DECLARE_CASE(cfunc_loadconfig_rejects_memlimit_overflow)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	/* memlimit is MiB; a value above INT_MAX>>10 would overflow the KiB
	 * field and must be rejected */
	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(&stream, "return { memlimit = 9999999 }")));
	T_EXPECT(
		strstr(ruleset_geterror(r, NULL), "memlimit too large") !=
		NULL);

	free_ruleset(loop, r);
	free(conf.strings);
}

T_DECLARE_CASE(cfunc_healthy_returns_hook_result_and_nil_when_absent)
{
	static const char with_healthy_chunk[] =
		"local ruleset = {} "
		"function ruleset.healthy() return true end "
		"return ruleset";
	static const char without_healthy_chunk[] = "local ruleset = {} "
						    "return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	/* hook present: cfunc_healthy calls it and returns its result */
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, with_healthy_chunk)));
	T_EXPECT(ruleset_pcall(r, cfunc_healthy, 0, 1));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	T_EXPECT(lua_toboolean(r->L, -1));
	lua_pop(r->L, 1);

	/* hook absent: cfunc_healthy returns nothing (nresults=1 pads to nil) */
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, without_healthy_chunk)));
	T_EXPECT(ruleset_pcall(r, cfunc_healthy, 0, 1));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	T_EXPECT(lua_isnil(r->L, -1));
	lua_pop(r->L, 1);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(cfunc_check_memlimit_collects_when_over_limit)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	lua_State *const L = r->L;

	/* a ruleset table must exist so the cfunc entry point's hook lookup does
	 * not index a nil global; cfunc_metrics runs check_memlimit first */
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, "return {}")));

	/* accumulate collectable garbage with the collector stopped so the live
	 * count sits well above a small limit */
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCSTOP, 0);
	T_CHECK(luaL_dostring(L, "for i = 1, 50000 do local t = { i } end") ==
		LUA_OK);
	const int before_kb = lua_gc(L, LUA_GCCOUNT, 0);

	/* a 1 KiB limit is far below current usage, so the next cfunc entry
	 * point must take check_memlimit's enforcement branch (LUA_GCCOLLECT) */
	r->config.memlimit_kb = 1;
	T_EXPECT(ruleset_pcall(r, cfunc_metrics, 0, 1));
	lua_pop(L, 1); /* metrics hook absent: padded nil */
	const int after_kb = lua_gc(L, LUA_GCCOUNT, 0);
	T_EXPECT(after_kb < before_kb);

	lua_gc(L, LUA_GCRESTART, 0);
	free_ruleset(loop, r);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(ruleset_loadfile_dispatches_requests),
	T_CASE(ruleset_dispatch_routes_by_address_type),
	T_CASE(ruleset_update_invoke_rpcall_stats_and_tick),
	T_CASE(ruleset_metrics_returns_string_when_defined_and_null_when_absent),
	T_CASE(ruleset_healthy_reports_unhealthy_string_and_null_when_ok),
	T_CASE(ruleset_cancel_pending_request_clears_callback),
	T_CASE(ruleset_state_detached_synchronously_on_completion),
	T_CASE(ruleset_geterror_variants),
	T_CASE(ruleset_isvalid_tracks_loaded_table),
	T_CASE(ruleset_load_missing_file_returns_false),
	T_CASE(cfunc_loadfile_stats_tick_and_invoke_are_sandboxed),
	T_CASE(cfunc_metrics_returns_string_when_defined_and_nil_when_absent),
	T_CASE(cfunc_update_replaces_loaded_module),
	T_CASE(cfunc_request_accepts_and_rejects),
	T_CASE(cfunc_request_reports_lua_error_via_callback),
	T_CASE(cfunc_rpcall_marshals_results_and_keeps_env_local),
	T_CASE(cfunc_rpcall_result_survives_gc_before_read),
	T_CASE(cfunc_rpcall_unmarshalable_result_reports_error),
	T_CASE(cfunc_rpcall_chunk_error_reports_failure),
	T_CASE(cfunc_rpcall_syntax_error_does_not_leak_thread),
	T_CASE(cfunc_request_malformed_dial_spec_is_rejected),
	T_CASE(cfunc_loadconfig_extracts_ruleset_and_settings),
	T_CASE(cfunc_loadconfig_rejects_non_table),
	T_CASE(cfunc_loadfile_rejects_non_table),
	T_CASE(cfunc_loadconfig_rejects_wrong_type_ruleset),
	T_CASE(cfunc_loadconfig_rejects_memlimit_overflow),
	T_CASE(cfunc_healthy_returns_hook_result_and_nil_when_absent),
	T_CASE(cfunc_check_memlimit_collects_when_over_limit),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
