/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset.h"

#include "conf.h"
#include "dialer.h"
#include "io/stream.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
#include "server.h"
#include "utils/testing.h"

#include "lauxlib.h"
#include "lua.h"

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
	T_EXPECT(strstr(rpc_result.result, "return ") == rpc_result.result);
	T_EXPECT(strstr(rpc_result.result, "42") != NULL);
	T_EXPECT(strstr(rpc_result.result, "done") != NULL);

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
	T_EXPECT(!wait_until(loop, request_fired, &result, 0.016));

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

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, ruleset_loadfile_dispatches_requests);
	T_RUN_CASE(t, ruleset_update_invoke_rpcall_stats_and_tick);
	T_RUN_CASE(
		t,
		ruleset_metrics_returns_string_when_defined_and_null_when_absent);
	T_RUN_CASE(t, ruleset_cancel_pending_request_clears_callback);
	T_RUN_CASE(t, ruleset_geterror_variants);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
