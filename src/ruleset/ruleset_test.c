/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * ruleset_test - white-box unit tests for ruleset.c and ruleset/cfunc.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset.c        module under test
 *   ruleset/cfunc.c  module under test (sandboxed C-function dispatch)
 *   ruleset/base.c   ruleset Lua substrate; its aux_traceback() is driven
 *                    here through the traceback configuration it serves,
 *                    end to end over a real request (base_test.c covers the
 *                    error-object renderings it heads a traceback with)
 *   conf.c           config data
 *   proto/codec.c    leaf
 *   version.c        leaf
 * The luaopen_* module entry points are replaced by the mocks in the mock
 * section below.
 */

#include "ruleset.h"

#include "base.h"
#include "cfunc.h"
#include "conf.h"
#include "dialer.h"
#include "proto/codec.h"
#include "server.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "utils/slog.h"
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

/* Constructor-only seams track the C object, cache, and VM allocations.
 * Ordinary cases use the unmodified allocator and real Lua constructor. */
enum constructor_failure {
	CONSTRUCTOR_OK,
	CONSTRUCTOR_OBJECT,
	CONSTRUCTOR_CACHE,
	CONSTRUCTOR_VM,
	CONSTRUCTOR_INIT,
};

static struct {
	bool tracking;
	enum constructor_failure failure;
	size_t calls;
	void *live[4096];
	size_t count;
	lua_Alloc alloc;
	bool fail_vm_alloc;
} CONSTRUCTOR;

void *test_ruleset_malloc(size_t size);
void *test_ruleset_realloc(void *ptr, size_t size);
void test_ruleset_free(void *ptr);
#if LUA_VERSION_NUM >= 505
lua_State *test_ruleset_newstate(lua_Alloc alloc, void *ud, unsigned int seed);
#else
lua_State *test_ruleset_newstate(lua_Alloc alloc, void *ud);
#endif

static void constructor_forget(void *ptr)
{
	if (!CONSTRUCTOR.tracking || ptr == NULL) {
		return;
	}
	for (size_t i = 0; i < CONSTRUCTOR.count; i++) {
		if (CONSTRUCTOR.live[i] == ptr) {
			CONSTRUCTOR.live[i] =
				CONSTRUCTOR.live[--CONSTRUCTOR.count];
			return;
		}
	}
	T_CHECK(false);
}

static void constructor_remember(void *ptr)
{
	if (CONSTRUCTOR.tracking && ptr != NULL) {
		T_CHECK(CONSTRUCTOR.count < ARRAY_SIZE(CONSTRUCTOR.live));
		CONSTRUCTOR.live[CONSTRUCTOR.count++] = ptr;
	}
}

void *test_ruleset_malloc(const size_t size)
{
	if (CONSTRUCTOR.tracking) {
		CONSTRUCTOR.calls++;
		if ((CONSTRUCTOR.failure == CONSTRUCTOR_OBJECT &&
		     CONSTRUCTOR.calls == 1) ||
		    (CONSTRUCTOR.failure == CONSTRUCTOR_CACHE &&
		     CONSTRUCTOR.calls == 2)) {
			return NULL;
		}
	}
	void *ptr = malloc(size);
	constructor_remember(ptr);
	return ptr;
}

void *test_ruleset_realloc(void *ptr, const size_t size)
{
	if (!CONSTRUCTOR.tracking || ptr == NULL) {
		void *next = realloc(ptr, size);
		constructor_remember(next);
		return next;
	}
	size_t idx = 0;
	for (; idx < CONSTRUCTOR.count; idx++) {
		if (CONSTRUCTOR.live[idx] == ptr) {
			break;
		}
	}
	T_CHECK(idx < CONSTRUCTOR.count);
	void *next = realloc(ptr, size);
	if (next != NULL) {
		CONSTRUCTOR.live[idx] = next;
	}
	return next;
}

void test_ruleset_free(void *ptr)
{
	constructor_forget(ptr);
	free(ptr);
}

static void *constructor_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (CONSTRUCTOR.fail_vm_alloc && nsize > 0 &&
	    (ptr == NULL || nsize > osize)) {
		return NULL;
	}
	return CONSTRUCTOR.alloc(ud, ptr, osize, nsize);
}

#if LUA_VERSION_NUM >= 505
lua_State *test_ruleset_newstate(lua_Alloc alloc, void *ud, unsigned int seed)
#else
lua_State *test_ruleset_newstate(lua_Alloc alloc, void *ud)
#endif
{
	if (CONSTRUCTOR.tracking && CONSTRUCTOR.failure == CONSTRUCTOR_VM) {
		return NULL;
	}
#if LUA_VERSION_NUM >= 505
	lua_State *L = lua_newstate(alloc, ud, seed);
#else
	lua_State *L = lua_newstate(alloc, ud);
#endif
	if (L != NULL && CONSTRUCTOR.tracking &&
	    CONSTRUCTOR.failure == CONSTRUCTOR_INIT) {
		CONSTRUCTOR.alloc = alloc;
		CONSTRUCTOR.fail_vm_alloc = true;
		lua_setallocf(L, constructor_alloc, ud);
	}
	return L;
}

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

/* A config a running daemon could actually hold: conf_loadfromtable rechecks
 * the field domains before it commits, so an out-of-range field here would
 * fail every load. */
static struct config make_conf(void)
{
	return (struct config){
		.listen = "127.0.0.1:1080",
		.resolve_pf = PF_UNSPEC,
		.timeout = 5.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
#if WITH_THREADS
		.workers = 1,
#endif
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

/* Log capture: the async error paths report to the log and nowhere else --
 * request_finish()/rpcall_finish() call LOGE_F after completing the callback --
 * so a writer sink collects every formatted line into a buffer a case then
 * searches. */
static struct {
	char buf[8192];
	size_t len;
} g_logcap;

static void logcap_write(void *ud, const unsigned char *buf, size_t len)
{
	(void)ud;
	const size_t space = sizeof(g_logcap.buf) - 1 - g_logcap.len;
	if (len > space) {
		len = space;
	}
	memcpy(g_logcap.buf + g_logcap.len, buf, len);
	g_logcap.len += len;
	g_logcap.buf[g_logcap.len] = '\0';
}

static void logcap_start(const int level)
{
	g_logcap.len = 0;
	g_logcap.buf[0] = '\0';
	slog_setoutput(SLOG_OUTPUT_WRITER, logcap_write, NULL);
	slog_setlevel(level);
}

/* Restore the default silence, so a case that longjmps out of an assertion
 * cannot leave the writer sink installed for the next one. */
static void logcap_stop(void)
{
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
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

T_DECLARE_CASE(ruleset_new_failure_cleanup)
{
	static const enum constructor_failure failures[] = {
		CONSTRUCTOR_OBJECT,
#if WITH_ALLOC_CACHE
		CONSTRUCTOR_CACHE,
#endif
		CONSTRUCTOR_VM,
		CONSTRUCTOR_INIT,
	};
	struct config conf = make_conf();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	for (size_t i = 0; i < ARRAY_SIZE(failures); i++) {
		CONSTRUCTOR.tracking = true;
		CONSTRUCTOR.failure = failures[i];
		CONSTRUCTOR.calls = 0;
		CONSTRUCTOR.count = 0;
		CONSTRUCTOR.fail_vm_alloc = false;
		struct ruleset *r = ruleset_new(loop, &conf, NULL, NULL);
		const size_t live = CONSTRUCTOR.count;
		CONSTRUCTOR.tracking = false;
		CONSTRUCTOR.fail_vm_alloc = false;
		T_EXPECT(r == NULL);
		T_EXPECT_EQ(live, 0);
		T_EXPECT_EQ(ev_pending_count(loop), 0);
		T_EXPECT_EQ(ev_run(loop, EVRUN_NOWAIT), 0);
	}
	/* Disarmed construction and teardown still use the same event loop. */
	CONSTRUCTOR.failure = CONSTRUCTOR_OK;
	CONSTRUCTOR.tracking = true;
	CONSTRUCTOR.calls = 0;
	CONSTRUCTOR.count = 0;
	struct ruleset *r = ruleset_new(loop, &conf, NULL, NULL);
	T_CHECK(r != NULL);
	ruleset_free(r);
	const size_t live = CONSTRUCTOR.count;
	CONSTRUCTOR.tracking = false;
	T_EXPECT_EQ(live, 0);
	T_EXPECT_EQ(ev_run(loop, EVRUN_NOWAIT), 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(cfunc_config_global_install_failure_is_atomic)
{
	for (int mode = 0; mode < 4; mode++) {
		const bool reload = (mode & 1) != 0;
		struct config conf = make_conf();
		conf.max_sessions = 7;
		struct ev_loop *loop = NULL;
		struct ruleset *r = new_ruleset(&loop, &conf);
		struct string_stream stream;
		/* Seed an owned string block so a failed replacement must preserve
		 * both field values and their original backing allocation. */
		T_CHECK(ruleset_pcall(
			r, cfunc_loadconfig, 1, 0,
			string_stream_open(
				&stream,
				"return {proxy = 'socks5://old:80'}")));
		char *old_strings = conf.strings;
		const char *old_proxy = conf.proxy;
		const int_least32_t old_limit = r->config.memlimit_kb;
		const bool old_traceback = r->config.traceback;
		lua_pushboolean(r->L, mode >= 2);
		lua_setglobal(r->L, "store_before_error");
		T_EXPECT(!ruleset_pcall(
			r, reload ? cfunc_reloadconfig : cfunc_loadconfig, 1, 0,
			string_stream_open(
				&stream,
				"setmetatable(_G, {__newindex = function(t,k,v) "
				"if k == 'ruleset' then "
				"if store_before_error then rawset(t,k,v) end "
				"error('refuse ruleset install') end "
				"rawset(t,k,v) end}) "
				"return {max_sessions=9, auth_required=true, proxy='socks5://new:81', "
				"memlimit=8, traceback=true, ruleset={}}")));
		T_EXPECT(
			strstr(ruleset_geterror(r, NULL),
			       "refuse ruleset install") != NULL);
		T_EXPECT_EQ(conf.max_sessions, 7);
		T_EXPECT(!conf.auth_required);
		T_EXPECT_EQ(conf.strings, old_strings);
		T_EXPECT_EQ(conf.proxy, old_proxy);
		T_EXPECT_STREQ(conf.proxy, "socks5://old:80");
		T_EXPECT_EQ(r->config.memlimit_kb, old_limit);
		T_EXPECT_EQ(r->config.traceback, old_traceback);
		T_EXPECT(!ruleset_isvalid(r));
		T_CHECK(luaL_dostring(r->L, "setmetatable(_G,nil)") == LUA_OK);
		T_EXPECT(ruleset_pcall(
			r, reload ? cfunc_reloadconfig : cfunc_loadconfig, 1, 0,
			string_stream_open(
				&stream,
				"return {max_sessions=9, auth_required=true, memlimit=8, traceback=true, ruleset={}}")));
		T_EXPECT_EQ(conf.max_sessions, 9);
		T_EXPECT(conf.auth_required);
		T_EXPECT_EQ(r->config.memlimit_kb, 8192);
		T_EXPECT(r->config.traceback);
		T_EXPECT(ruleset_isvalid(r));
		free_ruleset(loop, r);
		free(conf.strings);
	}
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
	char path[] = TEST_TMPDIR "/ruleset_test_XXXXXX";
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_CHECK(write_tempfile(path, script) == 0);
	T_EXPECT(ruleset_loadfile(r, path));

	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	const struct ruleset_credentials creds = {
		.username = "alice",
		.username_len = sizeof("alice") - 1,
		.password = "secret",
		.password_len = sizeof("secret") - 1,
	};
	T_EXPECT(ruleset_resolve(r, &state, "example.com:443", &creds, &cb));
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
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(80));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_route6(r, &state, "[::1]:53", NULL, &cb));
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
	char path[] = TEST_TMPDIR "/ruleset_test_XXXXXX";
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
		r, &state, "example.org:0", ATYP_DOMAIN, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(1));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_dispatch(
		r, &state, "203.0.113.1:0", ATYP_INET, NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	T_EXPECT_EQ(result.req->addr.port, UINT16_C(2));
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_dispatch(
		r, &state, "[2001:db8::9]:0", ATYP_INET6, NULL, &cb));
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

/*
 * ruleset_healthy() is the one consumer that hands ruleset_geterror()'s
 * message on to its own caller -- api_server.c writes it into the 503 body --
 * instead of logging it right away, so an error object the hook raised has to
 * arrive there rendered and still readable.
 */
T_DECLARE_CASE(ruleset_healthy_reports_a_raised_error_object)
{
	static const char chunk[] =
		"local ruleset = {} "
		"function ruleset.healthy() "
		"  error(setmetatable({ code = 7 }, { __tostring = "
		"    function(self) return 'down: code=' .. self.code end })) "
		"end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	size_t len = 0;

	T_EXPECT(install_ruleset(r, chunk));
	const char *const s = ruleset_healthy(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("down: code=7"));
	T_EXPECT_MEMEQ(s, "down: code=7", len);

	free_ruleset(loop, r);
}

/* ruleset_isvalid() gates the ruleset global at load time only, so ruleset Lua
 * can replace it with anything afterwards. Every hook must then read as absent
 * rather than raising "attempt to index a nil value": stats reports no ruleset
 * stats (an empty string, where NULL would mean the lookup failed), healthy
 * stays healthy (NULL, where a string would mark the service down), and the
 * ticker keeps running quietly. */
T_DECLARE_CASE(cfunc_hooks_are_absent_when_ruleset_global_is_not_a_table)
{
	static const char update_chunk[] =
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
		"  function ruleset.stats(dt, query) return 'live' end "
		"  function ruleset.metrics() return 'custom_metric 42\\n' end "
		"  function ruleset.healthy() return 'down: db' end "
		"  function ruleset.tick() _G.tick_count = (_G.tick_count or 0) + 1 end "
		"  return ruleset "
		"";
	static const char *const replacements[] = {
		"_G.ruleset = nil",
		"_G.ruleset = 42",
		"_G.ruleset = 'not a table'",
	};
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	size_t len = 0;
	const char *s;

	for (size_t i = 0; i < ARRAY_SIZE(replacements); i++) {
		T_EXPECT(ruleset_update(
			r, NULL, NULL,
			string_stream_open(&stream, update_chunk)));
		/* the hooks answer while the global is still the loaded table */
		T_EXPECT(ruleset_isvalid(r));
		s = ruleset_healthy(r, &len);
		T_CHECK(s != NULL);
		T_EXPECT_MEMEQ(s, "down: db", len);

		T_EXPECT(ruleset_invoke(
			r, string_stream_open(&stream, replacements[i])));
		T_EXPECT(!ruleset_isvalid(r));

		s = ruleset_stats(r, 1.5, "alpha", &len);
		T_CHECK(s != NULL);
		T_EXPECT_EQ(len, (size_t)0);
		T_EXPECT_EQ(ruleset_metrics(r, &len), NULL);
		T_EXPECT_EQ(ruleset_healthy(r, &len), NULL);
		/* the tick fires without raising, and runs no hook */
		ev_invoke(loop, &r->w_ticker, EV_TIMER);
		ev_invoke(loop, &r->w_idle, EV_IDLE);
		T_EXPECT(ruleset_invoke(
			r, string_stream_open(
				   &stream, "assert(_G.tick_count == nil)")));
	}

	free_ruleset(loop, r);
}

/* Assert _G.tick_count from inside the VM, so a mismatch reports the count. */
static bool expect_tick_count(struct ruleset *restrict r, const int want)
{
	char code[128];
	struct string_stream stream;

	(void)snprintf(
		code, sizeof(code),
		"local n = _G.tick_count or 0 "
		"assert(n == %d, 'tick_count = ' .. n)",
		want);
	return ruleset_invoke(r, string_stream_open(&stream, code));
}

/* A positive interval defers each tick to one idle iteration, so idle_cb
 * stops the idle watcher; neosocksd.setinterval(-1) sets the ticker's repeat
 * to 0, and the watcher must then stay active and tick on every iteration. */
T_DECLARE_CASE(ruleset_idle_cb_ticks_once_per_interval_and_always_when_idle)
{
	static const char chunk[] =
		"local ruleset = {} "
		"function ruleset.tick() "
		"  _G.tick_count = (_G.tick_count or 0) + 1 "
		"end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);

	T_EXPECT(install_ruleset(r, chunk));

	/* interval mode: one tick, then the idle watcher stops */
	T_CHECK(r->w_ticker.repeat > 0);
	ev_idle_start(loop, &r->w_idle);
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(!ev_is_active(&r->w_idle));
	T_EXPECT(expect_tick_count(r, 1));
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(expect_tick_count(r, 1));

	/* idle mode, as neosocksd.setinterval(-1) arms it */
	ev_timer_set(&r->w_ticker, 0.0, 0.0);
	ev_idle_start(loop, &r->w_idle);
	for (int i = 0; i < 3; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		T_EXPECT(ev_is_active(&r->w_idle));
	}
	T_EXPECT(expect_tick_count(r, 4));

	free_ruleset(loop, r);
}

/* A raising ruleset.tick is logged and otherwise swallowed: the ticker, and in
 * idle mode the idle watcher, keep running, so the next tick is still made. */
T_DECLARE_CASE(ruleset_idle_cb_logs_a_raising_tick_and_keeps_ticking)
{
	static const char chunk[] =
		"local ruleset = {} "
		"function ruleset.tick() "
		"  _G.tick_count = (_G.tick_count or 0) + 1 "
		"  error('tick boom ' .. _G.tick_count) "
		"end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);

	T_EXPECT(install_ruleset(r, chunk));

	/* interval mode: the periodic timer survives the raise */
	ev_timer_again(loop, &r->w_ticker);
	ev_idle_start(loop, &r->w_idle);
	logcap_start(LOG_LEVEL_WARNING);
	ev_run(loop, EVRUN_NOWAIT);
	logcap_stop();
	T_EXPECT(strstr(g_logcap.buf, "ruleset.tick: ") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "tick boom 1") != NULL);
	T_EXPECT(ev_is_active(&r->w_ticker));
	T_EXPECT(!ev_is_active(&r->w_idle));
	ev_timer_stop(loop, &r->w_ticker);

	/* idle mode: every iteration raises, and every one still ticks */
	ev_timer_set(&r->w_ticker, 0.0, 0.0);
	ev_idle_start(loop, &r->w_idle);
	for (int i = 2; i <= 3; i++) {
		char want[32];
		(void)snprintf(want, sizeof(want), "tick boom %d", i);
		logcap_start(LOG_LEVEL_WARNING);
		ev_run(loop, EVRUN_NOWAIT);
		logcap_stop();
		T_EXPECT(strstr(g_logcap.buf, "ruleset.tick: ") != NULL);
		T_EXPECT(strstr(g_logcap.buf, want) != NULL);
		T_EXPECT(ev_is_active(&r->w_idle));
	}
	T_EXPECT(expect_tick_count(r, 3));

	free_ruleset(loop, r);
}

/* ruleset_stats() returns NULL both for a raising hook, which is logged and
 * stored as the last error, and for a non-string result, which is silently
 * discarded; api_server.c then serves ruleset_geterror()'s text in its place,
 * as API.md documents. A number is converted rather than discarded. */
T_DECLARE_CASE(ruleset_stats_discards_non_strings_and_reports_a_raise)
{
#define STATS_CHUNK(body)                                                      \
	"local ruleset = {} "                                                  \
	"function ruleset.stats(dt, query) " body " end "                      \
	"return ruleset"
	static const char table_chunk[] = STATS_CHUNK("return {}");
	static const char nothing_chunk[] = STATS_CHUNK("return");
	static const char number_chunk[] = STATS_CHUNK("return 42");
	static const char raise_chunk[] =
		STATS_CHUNK("error('stats boom ' .. query)");
#undef STATS_CHUNK
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	size_t len = 0;
	const char *s;

	/* discarded results raise nothing: the last error is still unset */
	T_EXPECT(install_ruleset(r, table_chunk));
	logcap_start(LOG_LEVEL_WARNING);
	s = ruleset_stats(r, 1.0, "q", &len);
	logcap_stop();
	T_EXPECT_EQ(s, NULL);
	T_EXPECT_EQ(g_logcap.len, (size_t)0);
	T_EXPECT_STREQ(ruleset_geterror(r, NULL), "(nil)");

	T_EXPECT(install_ruleset(r, nothing_chunk));
	logcap_start(LOG_LEVEL_WARNING);
	s = ruleset_stats(r, 1.0, "q", &len);
	logcap_stop();
	T_EXPECT_EQ(s, NULL);
	T_EXPECT_EQ(g_logcap.len, (size_t)0);
	T_EXPECT_STREQ(ruleset_geterror(r, NULL), "(nil)");

	T_EXPECT(install_ruleset(r, number_chunk));
	s = ruleset_stats(r, 1.0, "q", &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen("42"));
	T_EXPECT_MEMEQ(s, "42", len);

	T_EXPECT(install_ruleset(r, raise_chunk));
	logcap_start(LOG_LEVEL_WARNING);
	s = ruleset_stats(r, 1.0, "alpha", &len);
	logcap_stop();
	T_EXPECT_EQ(s, NULL);
	T_EXPECT(strstr(g_logcap.buf, "ruleset.stats: ") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "stats boom alpha") != NULL);
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "stats boom alpha") != NULL);

	/* a later discarded result leaves that last error in place */
	T_EXPECT(install_ruleset(r, table_chunk));
	logcap_start(LOG_LEVEL_WARNING);
	s = ruleset_stats(r, 1.0, "q", &len);
	logcap_stop();
	T_EXPECT_EQ(s, NULL);
	T_EXPECT_EQ(g_logcap.len, (size_t)0);
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "stats boom alpha") != NULL);

	free_ruleset(loop, r);
}

/* Lua's own heap total counts the same nsize deltas l_alloc() sees, sizeof(LG)
 * included, so the two agree whenever every live block is Lua's own. */
static bool vmstats_match_lua_gc_count(struct ruleset *restrict r)
{
	struct ruleset_vmstats stats;
	lua_State *const L = r->L;

	ruleset_vmstats(r, &stats);
	const size_t total = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			     (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	if (stats.byt_allocated != total) {
		(void)fprintf(
			stderr, "byt_allocated = %zu, lua_gc = %zu\n",
			stats.byt_allocated, total);
		return false;
	}
	return true;
}

/* l_alloc() feeds neosocksd.stats() and /stats. Drive allocation, growth and
 * shrinking reallocs, and frees through the VM, and check its byte count
 * against Lua's after each, and its object count across one object's life.
 * lauxlib's string buffers allocate through l_alloc() directly, outside Lua's
 * count (and on 5.5 the resulting string keeps that block), so the buffer-built
 * string is compared only once a full collection has released it. */
T_DECLARE_CASE(ruleset_vmstats_track_lua_heap_allocations)
{
	static const char churn_chunk[] =
		"local t = {} "
		"for i = 1, 2000 do t[i] = ('x'):rep(i % 30) .. i end "
		"for i = 2000, 1, -1 do t[i] = nil end "
		"local h = {} "
		"for i = 1, 500 do h['k' .. i] = { i } end "
		"_G.kept = { t = t, h = h }";
	static const char buffer_chunk[] =
		"local t = {} "
		"for i = 1, 2000 do t[i] = ('x'):rep(i % 300) .. i end "
		"_G.kept.s = table.concat(t)";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_vmstats stats;
	struct string_stream stream;
	lua_State *const L = r->L;

	T_EXPECT(vmstats_match_lua_gc_count(r));
	T_EXPECT(install_ruleset(r, "return {}"));
	T_EXPECT(vmstats_match_lua_gc_count(r));
	T_EXPECT(ruleset_invoke(r, string_stream_open(&stream, churn_chunk)));
	T_EXPECT(vmstats_match_lua_gc_count(r));
	T_EXPECT(ruleset_invoke(r, string_stream_open(&stream, buffer_chunk)));
	T_EXPECT(ruleset_invoke(
		r, string_stream_open(&stream, "_G.kept.s = nil")));
	T_EXPECT(ruleset_gc(r));
	T_EXPECT(vmstats_match_lua_gc_count(r));
	T_EXPECT(ruleset_invoke(
		r, string_stream_open(&stream, "_G.kept = nil")));
	T_EXPECT(ruleset_gc(r));
	T_EXPECT(vmstats_match_lua_gc_count(r));

	/* one object: a table with no array or hash part is one allocation */
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCSTOP, 0);
	ruleset_vmstats(r, &stats);
	const size_t num_object = stats.num_object;
	lua_createtable(L, 0, 0);
	ruleset_vmstats(r, &stats);
	T_EXPECT_EQ(stats.num_object, num_object + 1);
	T_EXPECT(vmstats_match_lua_gc_count(r));
	lua_pop(L, 1);
	lua_gc(L, LUA_GCRESTART, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	ruleset_vmstats(r, &stats);
	T_EXPECT_EQ(stats.num_object, num_object);
	T_EXPECT(vmstats_match_lua_gc_count(r));

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
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
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
 * ruleset_request_cancel() covers the completed-but-undispatched window that
 * ruleset_cancel() cannot reach: request_finish() has already fed w_finish and
 * detached the state, so the callback alone still holds the delivered dialreq.
 * A consumer tearing its context down there must both drop the event and free
 * that request -- without the first the event fires into freed memory, without
 * the second the request leaks. The two windows on either side must stay
 * no-ops: nothing is delivered yet while the routine runs, and the consumer
 * already owns the request once the event has been dispatched.
 */
T_DECLARE_CASE(ruleset_request_cancel_drops_completed_undispatched_request)
{
	static const char sync_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) return request end "
		"return ruleset";
	static const char yield_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) coroutine.yield() end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;

	/* the completed-but-undispatched window: a non-yielding handler finishes
	 * inside ruleset_route(), leaving w_finish pending with the dialreq
	 * delivered but not yet taken over by the consumer */
	T_EXPECT(install_ruleset(r, sync_chunk));
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	T_EXPECT_EQ(state, NULL);
	T_EXPECT(ev_is_pending(&cb.w_finish));
	T_CHECK(cb.request.req != NULL);
	T_EXPECT_EQ(g_last_req, cb.request.req);

	ruleset_request_cancel(loop, &cb);
	T_EXPECT(!ev_is_pending(&cb.w_finish));
	T_EXPECT_EQ(cb.request.req, NULL);
	/* the mock dialreq_free() clears g_last_req, so the delivered request
	 * was really freed rather than merely dropped */
	T_EXPECT_EQ(g_last_req, NULL);
	/* the event is no longer pending (asserted above), so it cannot reach
	 * the consumer -- one non-blocking sweep confirms it without a wait */
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(!result.fired);

	/* still pending: the routine has not finished, so nothing was delivered
	 * and w_finish never went pending -- a no-op that must not disturb the
	 * live operation */
	T_EXPECT(install_ruleset(r, yield_chunk));
	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	T_CHECK(state != NULL);
	T_EXPECT_EQ(state->cb, &cb);
	T_EXPECT(!ev_is_pending(&cb.w_finish));
	ruleset_request_cancel(loop, &cb);
	T_EXPECT_EQ(state->cb, &cb);
	T_EXPECT_EQ(cb.request.req, NULL);
	T_EXPECT(!ev_is_pending(&cb.w_finish));
	ruleset_cancel(loop, state);
	T_EXPECT_EQ(state->cb, NULL);

	/* already dispatched: the consumer has taken the event and owns the
	 * request, so cancelling must not free it out from under them */
	T_EXPECT(install_ruleset(r, sync_chunk));
	result = (struct request_result){
		.callback = &cb,
	};
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT(!ev_is_pending(&cb.w_finish));
	ruleset_request_cancel(loop, &cb);
	T_EXPECT_EQ(cb.request.req, result.req);
	T_EXPECT_EQ(g_last_req, result.req);
	dialreq_free(result.req);

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
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
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

/* Record the object @p expr evaluates to as the last error, then check both
 * what ruleset_geterror() renders it as and what anchors that rendering: the
 * rendering replaces the stored object, so a repeat call is the very same
 * string and it outlives the stack it was built on. */
T_DECLARE_SUBCASE(
	check_geterror, struct ruleset *restrict r, const char *restrict expr,
	const char *restrict prefix)
{
	lua_State *restrict const L = r->L;
	const size_t prefixlen = strlen(prefix);

	lua_settop(L, 0);
	T_CHECK(luaL_loadstring(L, expr) == LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);

	size_t len = 0;
	const char *const s = ruleset_geterror(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_EQ(len, strlen(s));
	T_CHECK(len >= prefixlen);
	T_EXPECT_MEMEQ(s, prefix, prefixlen);
	T_EXPECT_EQ(ruleset_geterror(r, NULL), s);

	lua_settop(L, 0);
	(void)lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_MEMEQ(s, prefix, prefixlen);
}

/* Fail every allocation that grows, including the emergency-GC retry that
 * follows the first failure, while leaving the ruleset's own allocator (and
 * the ruleset pointer aux_getruleset() reads back from it) in place. A shrink
 * still succeeds: Lua 5.3 assumes the allocator never fails when osize >=
 * nsize, and shrinks the stack unprotected after every caught error. For a
 * new block (ptr == NULL) osize is a type tag, not a size. */
static struct {
	lua_Alloc alloc;
	void *ud;
	bool failing;
} g_alloc;

static void *
failing_alloc(void *ud, void *ptr, const size_t osize, const size_t nsize)
{
	if (g_alloc.failing && nsize > 0 && (ptr == NULL || nsize > osize)) {
		return NULL;
	}
	return g_alloc.alloc(ud, ptr, osize, nsize);
}

/*
 * ruleset_geterror() is the single funnel every consumer of a failed ruleset
 * operation reads -- the tick and request logs, ruleset load, the SIGHUP
 * reload, and the stats / metrics / healthy bodies the API serves. Whatever
 * the ruleset raised has to arrive there as its own message, so drive every
 * shape it can raise, then the two shortages that leave nothing to render it
 * with.
 */
T_DECLARE_CASE(ruleset_geterror_variants)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	lua_State *restrict const L = r->L;
	size_t len = 0;
	const char *err;

	/* nothing recorded reads as the fixed "no error" marker */
	err = ruleset_geterror(r, &len);
	T_EXPECT_EQ(len, strlen("(nil)"));
	T_EXPECT_MEMEQ(err, "(nil)", len);

	/* a string message passes through untouched */
	T_CALL_SUBCASE(check_geterror, r, "return 'sentinel'", "sentinel");
	/* other primitives render as tostring() would */
	T_CALL_SUBCASE(check_geterror, r, "return 42", "42");
	T_CALL_SUBCASE(check_geterror, r, "return true", "true");
	/* an object without __tostring: type and address */
	T_CALL_SUBCASE(check_geterror, r, "return {}", "table: ");
	/* a working __tostring carries the ruleset's own message */
	T_CALL_SUBCASE(
		check_geterror, r,
		"return setmetatable({ code = 7 }, { __tostring = "
		"function(self) return 'denied code=' .. self.code end })",
		"denied code=7");
	/* one that raises degrades to the description of the object */
	T_CALL_SUBCASE(
		check_geterror, r,
		"return setmetatable({}, { __tostring = "
		"function() error('tostring boom') end })",
		"(unprintable table: ");

	/* with the stack full there is no room to even read the stored object */
	lua_settop(L, 0);
	lua_newtable(L);
	lua_rawseti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR);
	/* Lua answers its first refusal by opening the reserve it keeps for
	 * error handling, so keep filling until a refusal repeats. */
	int refusals = 0;
	while (refusals < 2) {
		if (lua_checkstack(L, 2)) {
			lua_pushnil(L);
			refusals = 0;
			continue;
		}
		refusals++;
	}
	T_EXPECT_STREQ(ruleset_geterror(r, NULL), "(unprintable error object)");
	lua_settop(L, 0);

	/* out of memory defeats the rendering and the store alike, and the
	 * failure must not escape as a raise either */
	g_alloc.alloc = lua_getallocf(L, &g_alloc.ud);
	lua_setallocf(L, failing_alloc, g_alloc.ud);
	g_alloc.failing = true;
	err = ruleset_geterror(r, &len);
	g_alloc.failing = false;
	lua_setallocf(L, g_alloc.alloc, g_alloc.ud);
	T_EXPECT_STREQ(err, "(unprintable error object)");
	T_EXPECT_EQ(len, strlen(err));
	/* the store never happened, so the object is still what is on record */
	T_EXPECT_EQ(
		lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_LASTERROR), LUA_TTABLE);
	lua_pop(L, 1);

	ruleset_free(NULL);
	free_ruleset(loop, r);
}

/*
 * The `traceback' configuration arms three pieces of stack plumbing:
 * ruleset_pcallv() installs aux_traceback as its lua_pcall() errfunc,
 * aux_async() pushes it onto the coroutine for the handler call, and
 * thread_call_k() reinstalls it for the finish call. Drive the two ends where
 * the result is observable -- the error ruleset_geterror() reports and the one
 * request_finish() logs -- with the setting off as the control, so the "stack
 * traceback:" section is pinned to the configuration and not to whatever Lua
 * happens to produce.
 */
T_DECLARE_CASE(ruleset_traceback_config_reports_stack_traceback)
{
	static const char ruleset_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) error('route boom') end "
		"return ruleset";
	static const bool traceback[] = { false, true };

	for (size_t i = 0; i < ARRAY_SIZE(traceback); i++) {
		struct config conf = make_conf();
		conf.traceback = traceback[i];
		struct ev_loop *loop = NULL;
		struct ruleset *const r = new_ruleset(&loop, &conf);
		struct string_stream stream;
		struct ruleset_callback cb = { 0 };
		struct ruleset_state *state = NULL;
		struct request_result result = {
			.callback = &cb,
		};

		T_EXPECT_EQ(r->config.traceback, traceback[i]);

		/* the synchronous path: ruleset_pcallv()'s own errfunc, whose
		 * result is stored as the last error */
		T_EXPECT(!ruleset_invoke(
			r,
			string_stream_open(&stream, "error('invoke boom')")));
		const char *const err = ruleset_geterror(r, NULL);
		T_EXPECT(strstr(err, "invoke boom") != NULL);
		T_EXPECT_EQ(
			strstr(err, "stack traceback:") != NULL,
			(int)traceback[i]);

		/* the asynchronous path: the errfunc aux_async() installs decorates
		 * the handler's error before request_finish() logs it; the request
		 * itself is still rejected either way */
		T_EXPECT(install_ruleset(r, ruleset_chunk));
		ev_init(&cb.w_finish, request_finish_cb);
		cb.w_finish.data = &result;
		logcap_start(LOG_LEVEL_ERROR);
		T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
		logcap_stop();
		T_EXPECT(wait_until(
			loop, request_fired, &result, TEST_WAIT_SEC));
		T_EXPECT_EQ(result.req, NULL);
		T_EXPECT(strstr(g_logcap.buf, "ruleset error: ") != NULL);
		T_EXPECT(strstr(g_logcap.buf, "route boom") != NULL);
		T_EXPECT_EQ(
			strstr(g_logcap.buf, "stack traceback:") != NULL,
			(int)traceback[i]);

		free_ruleset(loop, r);
	}
}

/*
 * `traceback' asks for the stack on top of the message, but the message handler
 * it arms rendered a non-string error object from its type name and address
 * alone, so turning the setting on reported strictly less than the same error
 * reports with it off. Drive both ends the setting arms over an error object
 * that carries a message -- the synchronous errfunc, whose result is the stored
 * last error, and the asynchronous one, whose result request_finish() logs --
 * then repeat with a __tostring that raises, which must reach the fallback
 * instead of taking the report down with it.
 */
T_DECLARE_CASE(ruleset_traceback_keeps_the_error_message)
{
	static const char working_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  error(setmetatable({ code = 42 }, { __tostring = "
		"    function(self) return 'denied code=' .. self.code end })) "
		"end "
		"return ruleset";
	static const char raising_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  error(setmetatable({}, { __tostring = "
		"    function() error('tostring boom') end })) "
		"end "
		"return ruleset";
	struct config conf = make_conf();
	conf.traceback = true;
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(!ruleset_invoke(
		r,
		string_stream_open(
			&stream,
			"error(setmetatable({ code = 42 }, { __tostring = "
			"function(self) return 'denied code=' .. self.code end }))")));
	const char *const err = ruleset_geterror(r, NULL);
	T_EXPECT(strstr(err, "denied code=42") != NULL);
	T_EXPECT(strstr(err, "stack traceback:") != NULL);

	T_EXPECT(install_ruleset(r, working_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	logcap_start(LOG_LEVEL_ERROR);
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	logcap_stop();
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT(strstr(g_logcap.buf, "ruleset error: denied code=42") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "stack traceback:") != NULL);

	T_EXPECT(install_ruleset(r, raising_chunk));
	result = (struct request_result){
		.callback = &cb,
	};
	logcap_start(LOG_LEVEL_ERROR);
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
	logcap_stop();
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT(
		strstr(g_logcap.buf, "ruleset error: (unprintable table: ") !=
		NULL);
	T_EXPECT(strstr(g_logcap.buf, "stack traceback:") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "error in error handling") == NULL);

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
	char path[] = TEST_TMPDIR "/ruleset_test_XXXXXX";

	/* a fresh ruleset has no `ruleset' global yet */
	T_EXPECT(!ruleset_isvalid(r));

	T_CHECK(write_tempfile(path, script) == 0);
	T_EXPECT(ruleset_loadfile(r, path));
	/* after loading a table-returning script it is valid */
	T_EXPECT(ruleset_isvalid(r));

	(void)unlink(path);
	free_ruleset(loop, r);
}

/*
 * A boot config may install the common strict-globals guard, whose _G __index
 * raises for any undefined name, and still carry no `ruleset' field. The
 * validity check after the load must then read "no ruleset installed" instead
 * of letting the raise escape to the panic handler, which aborts the daemon.
 * The lookup still honours __index, like the hook dispatch it gates.
 */
T_DECLARE_CASE(ruleset_isvalid_survives_raising_global_lookup)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(
			&stream,
			"setmetatable(_G, { __index = function(_, k) "
			"  error('undefined global ' .. tostring(k), 2) "
			"end }) "
			"return {}")));
	T_EXPECT(!ruleset_isvalid(r));
	T_EXPECT(
		strstr(ruleset_geterror(r, NULL), "undefined global ruleset") !=
		NULL);

	/* an __index that supplies the table makes it valid */
	T_EXPECT(ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(
			&stream, "local proxy = {} "
				 "setmetatable(_G, { __index = function(_, k) "
				 "  if k == 'ruleset' then return proxy end "
				 "end }) "
				 "return {}")));
	T_EXPECT(ruleset_isvalid(r));

	free_ruleset(loop, r);
	free(conf.strings);
}

/*
 * A hook may return a number, which the API serves converted to its string
 * form. The conversion allocates, so it must run inside the protected call:
 * run after it, an out-of-memory raise reaches the panic handler and aborts.
 * The same holds for recording the "cannot open" error, which runs exactly
 * when opening the file may have failed for want of memory. Every hook result
 * is a fresh number, so its string form is never already interned and the
 * armed conversion has to allocate.
 */
T_DECLARE_CASE(ruleset_api_results_survive_oom)
{
	static const char chunk[] =
		"local ruleset = {} "
		"local n = 0 "
		"local function next() n = n + 1; return n + 0.5 end "
		"ruleset.stats = next "
		"ruleset.metrics = next "
		"ruleset.healthy = next "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	lua_State *restrict const L = r->L;
	size_t len = 0;
	const char *s;

	T_EXPECT(install_ruleset(r, chunk));
	/* unarmed, each number arrives as its string form */
	s = ruleset_stats(r, 1.0, NULL, &len);
	T_CHECK(s != NULL);
	T_EXPECT_MEMEQ(s, "1.5", len);
	s = ruleset_metrics(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_MEMEQ(s, "2.5", len);
	s = ruleset_healthy(r, &len);
	T_CHECK(s != NULL);
	T_EXPECT_MEMEQ(s, "3.5", len);

	/* keep any incidental collection from spending the failure elsewhere */
	(void)lua_gc(L, LUA_GCSTOP, 0);
	g_alloc.alloc = lua_getallocf(L, &g_alloc.ud);
	lua_setallocf(L, failing_alloc, g_alloc.ud);
	g_alloc.failing = true;
	const char *const stats = ruleset_stats(r, 1.0, NULL, &len);
	const char *const metrics = ruleset_metrics(r, &len);
	const char *const healthy = ruleset_healthy(r, &len);
	const bool loaded =
		ruleset_loadfile(r, TEST_TMPDIR "/missing/ruleset.lua");
	g_alloc.failing = false;
	lua_setallocf(L, g_alloc.alloc, g_alloc.ud);
	(void)lua_gc(L, LUA_GCRESTART, 0);

	/* each failure is reported as one, not raised */
	T_EXPECT_EQ(stats, NULL);
	T_EXPECT_EQ(metrics, NULL);
	T_CHECK(healthy != NULL);
	T_EXPECT(strstr(healthy, "not enough memory") != NULL);
	T_EXPECT(!loaded);
	T_EXPECT(
		strstr(ruleset_geterror(r, NULL), "not enough memory") != NULL);

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
	T_EXPECT(!ruleset_loadfile(r, TEST_TMPDIR "/missing/ruleset/path.lua"));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "cannot open") != NULL);
	T_EXPECT(!ruleset_loadconfig(
		r, TEST_TMPDIR "/missing/ruleset/config.lua"));
	T_EXPECT(strstr(ruleset_geterror(r, NULL), "cannot open") != NULL);

	free_ruleset(loop, r);
}

T_DECLARE_CASE(ruleset_new_clamps_oversized_memlimit)
{
	struct config conf = make_conf();
	/* the largest MiB value whose KiB form fits the int_least32_t field */
	conf.memlimit = (INT_LEAST32_MAX >> 10) + 1;
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);

	T_EXPECT_EQ(
		r->config.memlimit_kb,
		(int_least32_t)((INT_LEAST32_MAX >> 10) << 10));

	free_ruleset(loop, r);
}

/*
 * Regression: cfunc_loadconfig validates the ruleset-local memlimit only after
 * it had installed the new ruleset table and committed the config. A too-large
 * memlimit thus raised while the ruleset and config were already replaced. The
 * memlimit is now validated before any commit, so a late failure leaves both
 * the ruleset global and the config untouched.
 */
T_DECLARE_CASE(ruleset_loadconfig_late_memlimit_failure_is_atomic)
{
	struct config conf = make_conf();
	conf.max_sessions = 7;
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);

	/* no ruleset is installed to start with */
	T_EXPECT(!ruleset_isvalid(r));

	/* a config that would replace both the ruleset table and the config
	 * fields, but whose memlimit is too large to represent in KiB */
	char src[256];
	const long long huge = ((long long)INT_LEAST32_MAX >> 10) + 1;
	const int n = snprintf(
		src, sizeof(src),
		"return { listen = '127.0.0.1:1080', max_sessions = 99, "
		"ruleset = {}, memlimit = %lld }",
		huge);
	T_CHECK(n > 0 && (size_t)n < sizeof(src));
	char path[] = TEST_TMPDIR "/ruleset_test_cfg_XXXXXX";
	T_CHECK(write_tempfile(path, src) == 0);

	T_EXPECT(!ruleset_loadconfig(r, path));
	/* the config fields were not committed before the memlimit failure */
	T_EXPECT_EQ(conf.max_sessions, 7);
	/* nor was the new ruleset table installed */
	T_EXPECT(!ruleset_isvalid(r));

	(void)unlink(path);
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
	char path[] = TEST_TMPDIR "/cfunc_test_XXXXXX";
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

T_DECLARE_CASE(cfunc_update_nil_module_sets_true_everywhere)
{
	static const char mod_chunk[] = "local x = 1";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	seed_global_module(r->L, "demo");
	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, "demo", "=(demo)",
		string_stream_open(&stream, mod_chunk)));

	luaL_getsubtable(r->L, LUA_REGISTRYINDEX, "_LOADED");
	T_EXPECT_EQ(lua_getfield(r->L, -1, "demo"), LUA_TBOOLEAN);
	T_EXPECT(lua_toboolean(r->L, -1));
	T_EXPECT_EQ(lua_getglobal(r->L, "demo"), LUA_TBOOLEAN);
	T_EXPECT(lua_rawequal(r->L, -1, -2));
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
	const struct ruleset_credentials allow = {
		.username = "allow",
		.username_len = sizeof("allow") - 1,
		.password = "pw",
		.password_len = sizeof("pw") - 1,
	};
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", &allow,
		&cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_CHECK(result.req != NULL);
	T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
	dialreq_free(result.req);

	result = (struct request_result){
		.callback = &cb,
	};
	const struct ruleset_credentials deny = {
		.username = "deny",
		.username_len = sizeof("deny") - 1,
		.password = "pw",
		.password_len = sizeof("pw") - 1,
	};
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", &deny,
		&cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);

	free_ruleset(loop, r);
}

/* Regression: a credential is a byte string, not a null-terminated one. The
 * bytes and their length must both reach the callback, so a credential
 * carrying a null byte matches only itself: dropping the length would offer
 * the truncated prefix in its place, and the two identities below would
 * authenticate as one. */
T_DECLARE_CASE(cfunc_request_credentials_carry_null_bytes)
{
	static const char ruleset_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  if username == 'us\\0er' and #username == 5 and "
		"     password == 'pass\\0y' and #password == 6 then "
		"    return request "
		"  end "
		"  return nil "
		"end "
		"function ruleset.stats(dt, query) return '' end "
		"function ruleset.tick() end "
		"return ruleset";
	static const struct ruleset_credentials creds[] = {
		{
			.username = "us\0er",
			.username_len = 5,
			.password = "pass\0y",
			.password_len = 6,
		},
		/* the prefix a lost length would truncate them to */
		{
			.username = "us",
			.username_len = 2,
			.password = "pass",
			.password_len = 4,
		},
	};
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;

	T_EXPECT(install_ruleset(r, ruleset_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	for (size_t i = 0; i < ARRAY_SIZE(creds); i++) {
		struct request_result result = {
			.callback = &cb,
		};
		cb.w_finish.data = &result;
		T_EXPECT(ruleset_route(
			r, &state, "127.0.0.1:80", &creds[i], &cb));
		T_EXPECT(wait_until(
			loop, request_fired, &result, TEST_WAIT_SEC));
		if (i == 0) {
			T_CHECK(result.req != NULL);
			T_EXPECT_EQ(result.req->addr.type, ATYP_INET);
			dialreq_free(result.req);
			continue;
		}
		T_EXPECT_EQ(result.req, NULL);
	}

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
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", NULL,
		&cb));
	lua_pop(r->L, 1);
	T_EXPECT(wait_until(loop, request_fired, &result, TEST_WAIT_SEC));
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT_STREQ(ruleset_geterror(r, NULL), "(nil)");

	free_ruleset(loop, r);
}

/*
 * Regression: a rejected request reports nothing but the `ruleset error:` line
 * -- the callback carries only a NULL dialreq. Rendering the error object
 * dispatches __tostring, which ruleset Lua owns: when that raised, the raise
 * escaped request_finish, thread_call_k caught it into RIDX_LASTERROR (which
 * nothing on this path reads) and the line vanished entirely, exactly for the
 * errors an operator most needs to see. A working __tostring must still be
 * honored, so the fallback cannot simply replace the dispatch.
 */
T_DECLARE_CASE(cfunc_request_logs_error_that_cannot_be_rendered)
{
	static const char raising_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  error(setmetatable({}, "
		"    { __tostring = function() error('tostring boom') end })) "
		"end "
		"return ruleset";
	static const char working_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  error(setmetatable({ code = 42 }, "
		"    { __tostring = function(self) "
		"        return 'denied code=' .. self.code end })) "
		"end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct request_result result = {
		.callback = &cb,
	};

	T_EXPECT(install_ruleset(r, raising_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	logcap_start(LOG_LEVEL_ERROR);
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", NULL,
		&cb));
	lua_pop(r->L, 1);
	const bool fired =
		wait_until(loop, request_fired, &result, TEST_WAIT_SEC);
	logcap_stop();
	T_EXPECT(fired);
	/* the request is still rejected, as it always was */
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT(
		strstr(g_logcap.buf, "ruleset error: (unprintable table: ") !=
		NULL);

	T_EXPECT(install_ruleset(r, working_chunk));
	result = (struct request_result){
		.callback = &cb,
	};
	logcap_start(LOG_LEVEL_ERROR);
	T_EXPECT(ruleset_pcall(
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", NULL,
		&cb));
	lua_pop(r->L, 1);
	const bool fired_again =
		wait_until(loop, request_fired, &result, TEST_WAIT_SEC);
	logcap_stop();
	T_EXPECT(fired_again);
	T_EXPECT_EQ(result.req, NULL);
	T_EXPECT(strstr(g_logcap.buf, "ruleset error: denied code=42") != NULL);

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

/* The rpcall path drops the same line for the same reason: the caller gets a
 * NULL result and the `ruleset rpcall:` line is the only account of why. */
T_DECLARE_CASE(cfunc_rpcall_logs_error_that_cannot_be_rendered)
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
	logcap_start(LOG_LEVEL_ERROR);
	T_EXPECT(ruleset_pcall(
		r, cfunc_rpcall, 3, 1, &state,
		string_stream_open(
			&stream,
			"error(setmetatable({}, "
			"{ __tostring = function() error('tostring boom') end }))"),
		&cb));
	lua_pop(r->L, 1);
	const bool fired =
		wait_until(loop, rpcall_fired, &result, TEST_WAIT_SEC);
	logcap_stop();
	T_EXPECT(fired);
	T_EXPECT_EQ(result.result, NULL);
	T_EXPECT_EQ(result.resultlen, 0);
	T_EXPECT(
		strstr(g_logcap.buf, "ruleset rpcall: (unprintable table: ") !=
		NULL);

	free_ruleset(loop, r);
}

/* Resume the routine that parked itself in `hook.co` through the same
 * ruleset_resume() entry an await.* completion uses, pinning it under a
 * context key the way the await module does. */
static void resume_hooked_routine(struct ruleset *restrict r)
{
	static char ctx;
	lua_State *restrict const L = r->L;

	(void)lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	(void)lua_getglobal(L, "hook");
	(void)lua_getfield(L, -1, "co");
	T_CHECK(lua_isthread(L, -1));
	lua_rawsetp(L, -3, &ctx);
	lua_pop(L, 2);
	ruleset_resume(r, &ctx, 0);
	(void)lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_AWAIT_CONTEXT);
	lua_pushnil(L);
	lua_rawsetp(L, -2, &ctx);
	lua_settop(L, 0);
}

/*
 * Regression: the finish closures skipped everything once the consumer was
 * gone -- the client cancelled, or await.forward() committed the request --
 * and the error line sat below that early return. The finish closure is the
 * only place a routine's error is reported, so a handler that raised after
 * its client went away left no trace at any log level. Nothing may be
 * delivered to the torn-down consumer, but the error must still be logged; a
 * routine that ends normally there stays silent.
 */
T_DECLARE_CASE(cfunc_request_finish_logs_error_after_cancel)
{
	static const char ruleset_chunk[] =
		"local modname = ... "
		"local ruleset = {} "
		"function ruleset.route(request, username, password) "
		"  hook.co = coroutine.running() "
		"  coroutine.yield() "
		"  if hook.fail then error('late route boom') end "
		"  return request "
		"end "
		"return ruleset";
	static const bool fail[] = { false, true };
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	lua_State *restrict const L = r->L;
	struct ruleset_callback cb = { 0 };
	struct request_result result = {
		.callback = &cb,
	};

	lua_newtable(L);
	lua_setglobal(L, "hook");
	T_EXPECT(install_ruleset(r, ruleset_chunk));
	ev_init(&cb.w_finish, request_finish_cb);
	cb.w_finish.data = &result;
	for (size_t i = 0; i < ARRAY_SIZE(fail); i++) {
		(void)lua_getglobal(L, "hook");
		lua_pushboolean(L, fail[i]);
		lua_setfield(L, -2, "fail");
		lua_pop(L, 1);
		struct ruleset_state *state = NULL;
		T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &cb));
		T_CHECK(state != NULL);
		/* the client goes away while the handler waits */
		ruleset_cancel(loop, state);
		logcap_start(LOG_LEVEL_ERROR);
		resume_hooked_routine(r);
		logcap_stop();
		/* nothing is delivered to the cancelled consumer */
		T_EXPECT(!ev_is_pending(&cb.w_finish));
		T_EXPECT(!result.fired);
		if (fail[i]) {
			T_EXPECT(
				strstr(g_logcap.buf, "ruleset error: ") !=
				NULL);
			T_EXPECT(
				strstr(g_logcap.buf, "late route boom") !=
				NULL);
		} else {
			T_EXPECT_EQ(g_logcap.len, (size_t)0);
		}
	}

	free_ruleset(loop, r);
}

/* Regression: the rpcall counterpart of the case above -- an rpcall chunk
 * that raised after its HTTP client disconnected was not logged. */
T_DECLARE_CASE(cfunc_rpcall_finish_logs_error_after_cancel)
{
	static const char rpcall_chunk[] = "hook.co = coroutine.running() "
					   "coroutine.yield() "
					   "error('late rpcall boom')";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	lua_State *restrict const L = r->L;
	struct string_stream stream;
	struct ruleset_callback cb = { 0 };
	struct ruleset_state *state = NULL;
	struct rpcall_result result = {
		.callback = &cb,
	};

	lua_newtable(L);
	lua_setglobal(L, "hook");
	ev_init(&cb.w_finish, rpcall_finish_cb);
	cb.w_finish.data = &result;
	T_EXPECT(ruleset_rpcall(
		r, &state, string_stream_open(&stream, rpcall_chunk), &cb));
	T_CHECK(state != NULL);
	/* the HTTP client disconnects mid-chunk */
	ruleset_cancel(loop, state);
	logcap_start(LOG_LEVEL_ERROR);
	resume_hooked_routine(r);
	logcap_stop();
	T_EXPECT(!ev_is_pending(&cb.w_finish));
	T_EXPECT(!result.fired);
	T_EXPECT(strstr(g_logcap.buf, "ruleset rpcall: ") != NULL);
	T_EXPECT(strstr(g_logcap.buf, "late rpcall boom") != NULL);

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

/*
 * ruleset_state_gc() is the last-resort safety net for an asynchronous
 * operation started but never finished: collected with its callback still
 * attached, the state must clear the result through the union and complete the
 * callback rather than strand the consumer on an event nothing can feed.
 *
 * A routine that suspends without awaiting anything reaches it
 * deterministically. Only RIDX_AWAIT_CONTEXT stores the coroutine itself;
 * RIDX_FORWARD_CONTEXT is keyed and valued by raw pointers, which hold no
 * reference. So once the state userdata the cfunc returned is popped, nothing
 * reaches the suspended coroutine or the finish closure carrying the state.
 */
T_DECLARE_CASE(ruleset_state_gc_completes_orphaned_async_ops)
{
	static const char yield_chunk[] =
		"local ruleset = {} "
		"function ruleset.route(request, username, password) coroutine.yield() end "
		"return ruleset";
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	struct ruleset_callback rpc_cb = { 0 };
	struct ruleset_callback req_cb = { 0 };
	struct ruleset_state *state = NULL;
	struct rpcall_result rpc_result = {
		.callback = &rpc_cb,
	};
	struct request_result req_result = {
		.callback = &req_cb,
	};

	/* the rpcall arm */
	ev_init(&rpc_cb.w_finish, rpcall_finish_cb);
	rpc_cb.w_finish.data = &rpc_result;
	T_EXPECT(ruleset_pcall(
		r, cfunc_rpcall, 3, 1, &state,
		string_stream_open(&stream, "coroutine.yield()"), &rpc_cb));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	lua_pop(r->L, 1);
	T_CHECK(state != NULL);
	T_EXPECT_EQ(state->cb, &rpc_cb);
	/* the operation is suspended: nothing has completed it */
	T_EXPECT(!ev_is_pending(&rpc_cb.w_finish));
	T_EXPECT(!rpc_result.fired);

	/* Seed the union with a sentinel the finalizer must overwrite. It
	 * clears either arm through rpcall.result, relying on request.req
	 * sharing offset 0; against a zeroed callback that clear would be
	 * indistinguishable from doing nothing. */
	rpc_cb.rpcall.result = "stale";
	rpc_cb.rpcall.resultlen = sizeof("stale") - 1;

	/* dropping the last reference must hand the callback back rather than
	 * strand the consumer; state_complete() also detaches the caller's own
	 * storage slot synchronously */
	lua_gc(r->L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(state, NULL);
	T_EXPECT(ev_is_pending(&rpc_cb.w_finish));
	T_EXPECT(wait_until(loop, rpcall_fired, &rpc_result, TEST_WAIT_SEC));
	T_EXPECT_EQ(rpc_result.result, NULL);
	T_EXPECT_EQ(rpc_result.resultlen, (size_t)0);

	/* the request arm, where the same finalizer clears request.req */
	T_EXPECT(install_ruleset(r, yield_chunk));
	ev_init(&req_cb.w_finish, request_finish_cb);
	req_cb.w_finish.data = &req_result;
	T_EXPECT(ruleset_route(r, &state, "127.0.0.1:80", NULL, &req_cb));
	T_EXPECT_EQ(lua_gettop(r->L), 1);
	lua_pop(r->L, 1);
	T_CHECK(state != NULL);
	T_EXPECT_EQ(state->cb, &req_cb);
	T_EXPECT(!ev_is_pending(&req_cb.w_finish));

	/* the same sentinel idea on the request arm: a delivered request the
	 * finalizer must replace with NULL, so the consumer is not handed one
	 * nobody owns */
	struct dialreq *const seed = dialreq_new(NULL, 0);
	T_CHECK(seed != NULL);
	req_cb.request.req = seed;

	lua_gc(r->L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(state, NULL);
	T_EXPECT(ev_is_pending(&req_cb.w_finish));
	T_EXPECT(wait_until(loop, request_fired, &req_result, TEST_WAIT_SEC));
	T_EXPECT_EQ(req_result.req, NULL);
	dialreq_free(seed);

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
		r, cfunc_request, 5, 1, &state, "route", "127.0.0.1:80", NULL,
		&cb));
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

/* The integer `tag' of the installed global ruleset table, or -1 when none. */
static lua_Integer ruleset_tag(lua_State *restrict L)
{
	lua_Integer tag = -1;
	if (lua_getglobal(L, "ruleset") == LUA_TTABLE) {
		lua_getfield(L, -1, "tag");
		tag = lua_tointeger(L, -1);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
	return tag;
}

/*
 * A SIGHUP reload of the boot config must refuse what the running server
 * cannot honor -- auth_required with no ruleset to check the credentials, or a
 * change to a listener set up at startup -- before anything is committed: the
 * config keeps its values and an installed ruleset is not replaced by the
 * refused table's.
 */
T_DECLARE_CASE(cfunc_reloadconfig_refuses_before_commit)
{
	struct config conf = make_conf();
	conf.max_sessions = 7;
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	/* no ruleset installed, and the table brings none */
	T_EXPECT(!ruleset_pcall(
		r, cfunc_reloadconfig, 1, 0,
		string_stream_open(
			&stream,
			"return { auth_required = true, max_sessions = 9 }")));
	T_EXPECT(!conf.auth_required);
	T_EXPECT_EQ(conf.max_sessions, 7);
	T_EXPECT(!ruleset_isvalid(r));

	/* the table installs one */
	T_EXPECT(ruleset_pcall(
		r, cfunc_reloadconfig, 1, 0,
		string_stream_open(
			&stream,
			"return { auth_required = true, ruleset = { tag = 1 } }")));
	T_EXPECT(conf.auth_required);
	T_EXPECT_EQ(ruleset_tag(r->L), 1);

	/* the ruleset already installed stays in place */
	T_EXPECT(ruleset_pcall(
		r, cfunc_reloadconfig, 1, 0,
		string_stream_open(&stream, "return { max_sessions = 9 }")));
	T_EXPECT(conf.auth_required);
	T_EXPECT_EQ(conf.max_sessions, 9);
	T_EXPECT_EQ(ruleset_tag(r->L), 1);

	/* a listener change is refused along with the ruleset it carries */
	T_EXPECT(!ruleset_pcall(
		r, cfunc_reloadconfig, 1, 0,
		string_stream_open(
			&stream,
			"return { listen = '127.0.0.1:1081', max_sessions = 11, "
			"ruleset = { tag = 2 } }")));
	T_EXPECT_STREQ(conf.listen, "127.0.0.1:1080");
	T_EXPECT_EQ(conf.max_sessions, 9);
	T_EXPECT_EQ(ruleset_tag(r->L), 1);

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

/*
 * Regression: cfunc_loadconfig ran the config chunk under an inner pcall and
 * re-raised its error, so the chunk's frames were unwound before the traceback
 * handler ruleset_pcallv() arms could see them, and a failing config reported
 * only "[C]: in ?". The traceback must reach into the chunk, as it does for a
 * ruleset file.
 */
T_DECLARE_CASE(cfunc_loadconfig_traceback_reaches_the_chunk)
{
	struct config conf = make_conf();
	conf.traceback = true;
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;

	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadconfig, 1, 0,
		string_stream_open(
			&stream,
			"local function inner() error('config boom') end\n"
			"local function outer() inner() end\n"
			"outer()\n"
			"return {}\n")));
	const char *const err = ruleset_geterror(r, NULL);
	T_EXPECT(strstr(err, "config boom") != NULL);
	const char *const tb = strstr(err, "stack traceback:");
	T_CHECK(tb != NULL);
	T_EXPECT(strstr(tb, "'inner'") != NULL);
	T_EXPECT(strstr(tb, "'outer'") != NULL);
	T_EXPECT(strstr(tb, "in main chunk") != NULL);

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

	/* memlimit is MiB; a value above INT_LEAST32_MAX>>10 would overflow
	 * the int_least32_t KiB field and must be rejected */
	char chunk[64];
	(void)snprintf(
		chunk, sizeof(chunk), "return { memlimit = %jd }",
		(intmax_t)(INT_LEAST32_MAX >> 10) + 1);
	T_EXPECT(!ruleset_pcall(
		r, cfunc_loadconfig, 1, 0, string_stream_open(&stream, chunk)));
	T_EXPECT(
		strstr(ruleset_geterror(r, NULL), "memlimit too large") !=
		NULL);

	/* a non-integer memlimit is rejected by field name, including the float
	 * and numeric-string forms an argument checker would coerce */
	static const char *const non_integer[] = {
		"return { memlimit = 1.5 }",  "return { memlimit = 2.0 }",
		"return { memlimit = 'x' }",  "return { memlimit = '64' }",
		"return { memlimit = true }",
	};
	for (size_t i = 0; i < ARRAY_SIZE(non_integer); i++) {
		T_EXPECT(!ruleset_pcall(
			r, cfunc_loadconfig, 1, 0,
			string_stream_open(&stream, non_integer[i])));
		const char *const err = ruleset_geterror(r, NULL);
		if (strstr(err,
			   "config: field `memlimit' must be an integer") ==
		    NULL) {
			T_LOGF("%s: %s", non_integer[i], err);
			T_FAIL();
		}
	}
	T_EXPECT_EQ(r->config.memlimit_kb, (int_least32_t)0);

	/* the boundary value itself is accepted */
	(void)snprintf(
		chunk, sizeof(chunk), "return { memlimit = %jd }",
		(intmax_t)(INT_LEAST32_MAX >> 10));
	T_EXPECT(ruleset_pcall(
		r, cfunc_loadconfig, 1, 0, string_stream_open(&stream, chunk)));
	T_EXPECT_EQ(
		r->config.memlimit_kb,
		(int_least32_t)((INT_LEAST32_MAX >> 10) << 10));

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

/*
 * check_memlimit judges the limit against the allocator's total, not
 * LUA_GCCOUNT: strings lauxlib builds in a buffer box are allocated outside
 * Lua's own count (for their whole life on Lua 5.5, where they become
 * external strings), yet they are ruleset memory the limit must bound.
 */
T_DECLARE_CASE(cfunc_check_memlimit_counts_buffer_built_strings)
{
	struct config conf = make_conf();
	struct ev_loop *loop = NULL;
	struct ruleset *const r = new_ruleset(&loop, &conf);
	struct string_stream stream;
	lua_State *const L = r->L;

	T_EXPECT(ruleset_pcall(
		r, cfunc_update, 3, 0, NULL, "=test",
		string_stream_open(&stream, "return {}")));

	/* build 64 strings of 8 KiB through table.concat's buffer, then drop
	 * them all at once, leaving them as garbage the collector has not seen */
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCSTOP, 0);
	T_CHECK(luaL_dostring(
			L, "local t = {} "
			   "for i = 1, 8192 do t[i] = 'x' end "
			   "built = {} "
			   "for i = 1, 64 do built[i] = table.concat(t) end "
			   "built = nil") == LUA_OK);
	const size_t before = r->vmstats.byt_allocated;
	const int_least32_t limit_kb = (int_least32_t)(before >> 10);
#if LUA_VERSION_NUM >= 505
	/* the built strings are outside Lua's count, so it sits below the limit */
	T_EXPECT(lua_gc(L, LUA_GCCOUNT, 0) < limit_kb);
#endif

	/* the allocator's total has reached the limit: the next cfunc entry
	 * point must collect, returning the built strings to the allocator */
	r->config.memlimit_kb = limit_kb;
	T_EXPECT(ruleset_pcall(r, cfunc_metrics, 0, 1));
	lua_pop(L, 1); /* metrics hook absent: padded nil */
	const size_t after = r->vmstats.byt_allocated;
	T_EXPECT(after + (size_t)64 * 8192 < before);

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
	T_CASE(ruleset_new_failure_cleanup),
	T_CASE(cfunc_config_global_install_failure_is_atomic),
	T_CASE(ruleset_loadfile_dispatches_requests),
	T_CASE(ruleset_dispatch_routes_by_address_type),
	T_CASE(ruleset_update_invoke_rpcall_stats_and_tick),
	T_CASE(ruleset_metrics_returns_string_when_defined_and_null_when_absent),
	T_CASE(ruleset_healthy_reports_unhealthy_string_and_null_when_ok),
	T_CASE(ruleset_healthy_reports_a_raised_error_object),
	T_CASE(ruleset_idle_cb_ticks_once_per_interval_and_always_when_idle),
	T_CASE(ruleset_idle_cb_logs_a_raising_tick_and_keeps_ticking),
	T_CASE(ruleset_stats_discards_non_strings_and_reports_a_raise),
	T_CASE(ruleset_vmstats_track_lua_heap_allocations),
	T_CASE(ruleset_cancel_pending_request_clears_callback),
	T_CASE(ruleset_request_cancel_drops_completed_undispatched_request),
	T_CASE(ruleset_state_detached_synchronously_on_completion),
	T_CASE(ruleset_geterror_variants),
	T_CASE(ruleset_traceback_config_reports_stack_traceback),
	T_CASE(ruleset_traceback_keeps_the_error_message),
	T_CASE(ruleset_isvalid_tracks_loaded_table),
	T_CASE(ruleset_isvalid_survives_raising_global_lookup),
	T_CASE(ruleset_api_results_survive_oom),
	T_CASE(ruleset_load_missing_file_returns_false),
	T_CASE(ruleset_new_clamps_oversized_memlimit),
	T_CASE(ruleset_loadconfig_late_memlimit_failure_is_atomic),
	T_CASE(cfunc_loadfile_stats_tick_and_invoke_are_sandboxed),
	T_CASE(cfunc_metrics_returns_string_when_defined_and_nil_when_absent),
	T_CASE(cfunc_update_replaces_loaded_module),
	T_CASE(cfunc_update_nil_module_sets_true_everywhere),
	T_CASE(cfunc_request_accepts_and_rejects),
	T_CASE(cfunc_request_credentials_carry_null_bytes),
	T_CASE(cfunc_request_reports_lua_error_via_callback),
	T_CASE(cfunc_request_logs_error_that_cannot_be_rendered),
	T_CASE(cfunc_rpcall_marshals_results_and_keeps_env_local),
	T_CASE(cfunc_rpcall_result_survives_gc_before_read),
	T_CASE(cfunc_rpcall_unmarshalable_result_reports_error),
	T_CASE(cfunc_rpcall_chunk_error_reports_failure),
	T_CASE(cfunc_rpcall_logs_error_that_cannot_be_rendered),
	T_CASE(cfunc_request_finish_logs_error_after_cancel),
	T_CASE(cfunc_rpcall_finish_logs_error_after_cancel),
	T_CASE(cfunc_rpcall_syntax_error_does_not_leak_thread),
	T_CASE(ruleset_state_gc_completes_orphaned_async_ops),
	T_CASE(cfunc_request_malformed_dial_spec_is_rejected),
	T_CASE(cfunc_loadconfig_extracts_ruleset_and_settings),
	T_CASE(cfunc_reloadconfig_refuses_before_commit),
	T_CASE(cfunc_loadconfig_rejects_non_table),
	T_CASE(cfunc_loadconfig_traceback_reaches_the_chunk),
	T_CASE(cfunc_loadfile_rejects_non_table),
	T_CASE(cfunc_loadconfig_rejects_wrong_type_ruleset),
	T_CASE(cfunc_loadconfig_rejects_memlimit_overflow),
	T_CASE(cfunc_healthy_returns_hook_result_and_nil_when_absent),
	T_CASE(cfunc_hooks_are_absent_when_ruleset_global_is_not_a_table),
	T_CASE(cfunc_check_memlimit_collects_when_over_limit),
	T_CASE(cfunc_check_memlimit_counts_buffer_built_strings),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
