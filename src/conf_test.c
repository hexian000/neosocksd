/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for conf.c. */

#include "conf.h"

#if WITH_LUA
#include "proto/codec.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#endif /* WITH_LUA */

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - bounded string sizing and allocation faults.
 * ---------------------------------------------------------------------- */

static const size_t *mock_string_lengths;
static size_t mock_string_count;
static size_t mock_string_index;
static size_t mock_alloc_count;
static size_t mock_alloc_size;

size_t test_conf_strlen(const char *str)
{
	if (mock_string_lengths != NULL &&
	    mock_string_index < mock_string_count) {
		return mock_string_lengths[mock_string_index++];
	}
	return strlen(str);
}

void *test_conf_malloc(const size_t size)
{
	if (mock_string_lengths != NULL) {
		mock_alloc_count++;
		mock_alloc_size = size;
		return NULL;
	}
	return malloc(size);
}

struct conf_fixture {
	struct config conf;
	char *capture;
	char *path;
#if WITH_LUA
	lua_State *L;
	struct vbuffer *buffer;
	struct io_stream *writer;
#endif /* WITH_LUA */
	struct conf_fixture *next;
};

static struct conf_fixture *fixtures;
static unsigned live_fixtures, released_captures;
#if WITH_LUA
static unsigned live_lua, released_writers, released_buffers;
#endif /* WITH_LUA */

static void clear_config(struct config *conf)
{
	free(conf->strings);
	conf->strings = NULL;
}

#if WITH_LUA
static void close_test_lua(lua_State *L)
{
	for (struct conf_fixture *f = fixtures; f != NULL; f = f->next) {
		if (f->L == L) {
			lua_close(L);
			f->L = NULL;
			live_lua--;
			return;
		}
	}
	T_CHECK(false);
}
#endif /* WITH_LUA */

static void cleanup_fixtures(void *data)
{
	(void)data;
	while (fixtures != NULL) {
		struct conf_fixture *f = fixtures;
		if (f->capture != NULL) {
			free(f->capture);
			released_captures++;
		}
		if (f->path != NULL) {
			(void)unlink(f->path);
			free(f->path);
		}
#if WITH_LUA
		if (f->L != NULL) {
			close_test_lua(f->L);
		}
		if (f->writer != NULL) {
			(void)io_stream_close(f->writer);
			released_writers++;
		}
		if (f->buffer != NULL) {
			VBUF_FREE(f->buffer);
			released_buffers++;
		}
#endif /* WITH_LUA */
		clear_config(&f->conf);
		fixtures = f->next;
		free(f);
		live_fixtures--;
	}
	mock_string_lengths = NULL;
}

static struct conf_fixture *new_fixture(struct testing_ctx *_t_)
{
	struct conf_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	if (fixtures == NULL) {
		T_CLEANUP(cleanup_fixtures, NULL);
	}
	f->next = fixtures;
	fixtures = f;
	live_fixtures++;
	return f;
}

#if WITH_LUA
static struct config *new_config(struct testing_ctx *_t_, struct config value)
{
	struct conf_fixture *f = new_fixture(_t_);
	f->conf = value;
	return &f->conf;
}

static lua_State *new_test_lua(struct testing_ctx *_t_)
{
	struct conf_fixture *f = new_fixture(_t_);
	f->L = luaL_newstate();
	T_CHECK(f->L != NULL);
	live_lua++;
	return f->L;
}

static bool boot_oom;
static lua_Alloc boot_alloc;
static size_t boot_vm_closed;
static size_t boot_stream_closed;
static size_t boot_alloc_failures;

static void *boot_failing_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (boot_oom && nsize > 0 && (ptr == NULL || nsize > osize)) {
		boot_alloc_failures++;
		return NULL;
	}
	return boot_alloc(ud, ptr, osize, nsize);
}

lua_State *test_conf_newstate(void)
{
	lua_State *L = luaL_newstate();
	if (L != NULL && boot_oom) {
		void *ud;
		boot_alloc = lua_getallocf(L, &ud);
		lua_setallocf(L, boot_failing_alloc, ud);
	}
	return L;
}

void test_conf_close(lua_State *L)
{
	if (boot_oom) {
		boot_vm_closed++;
	}
	lua_close(L);
}

int test_conf_stream_close(struct io_stream *stream)
{
	if (boot_oom) {
		boot_stream_closed++;
	}
	return io_stream_close(stream);
}
#endif /* WITH_LUA */

static struct config make_valid_conf(void)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	return conf;
}

/* Redirect fd_no (STDOUT_FILENO or STDERR_FILENO) to a temporary file, run
 * action(data), restore fd_no, and return fixture-owned captured bytes.
 * Returns NULL on any setup/I/O failure or when action returns false. */
static char *capture_fd(
	struct testing_ctx *_t_, const int fd_no, bool (*action)(const void *),
	const void *data)
{
	FILE *const stream = (fd_no == STDOUT_FILENO) ? stdout : stderr;
	(void)fflush(stream);
	const int saved_fd = dup(fd_no);
	if (saved_fd < 0) {
		return NULL;
	}
	char path[] = TEST_TMPDIR "/conf_capture_XXXXXX";
	const int tmp_fd = mkstemp(path);
	if (tmp_fd < 0) {
		(void)close(saved_fd);
		return NULL;
	}
	(void)unlink(path);
	FILE *const tmp = fdopen(tmp_fd, "w+");
	if (tmp == NULL) {
		(void)close(tmp_fd);
		(void)close(saved_fd);
		return NULL;
	}
	if (dup2(fileno(tmp), fd_no) < 0) {
		(void)fclose(tmp);
		(void)close(saved_fd);
		return NULL;
	}

	const bool ok = action(data);

	(void)fflush(stream);
	(void)dup2(saved_fd, fd_no);
	(void)close(saved_fd);

	if (!ok) {
		(void)fclose(tmp);
		return NULL;
	}
	const long size = ftell(tmp);
	if (size < 0) {
		(void)fclose(tmp);
		return NULL;
	}
	if (fseek(tmp, 0, SEEK_SET) != 0) {
		(void)fclose(tmp);
		return NULL;
	}
	char *const buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		(void)fclose(tmp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, tmp);
	(void)fclose(tmp);
	buf[n] = '\0';
	struct conf_fixture *f = new_fixture(_t_);
	f->capture = buf;
	return buf;
}

#if WITH_LUA
static bool run_conf_print(const void *data)
{
	return conf_print(data);
}

/* Capture stdout in a fixture-owned buffer; returns NULL on failure. */
static char *
capture_conf_print(struct testing_ctx *_t_, const struct config *restrict conf)
{
	return capture_fd(_t_, STDOUT_FILENO, run_conf_print, conf);
}

/* Load a conf_print() dump as a Lua chunk and return the resulting table
 * (pushed on top of the stack); the caller owns closing L. */
static bool load_printed_conf(lua_State *restrict L, const char *restrict src)
{
	return luaL_loadstring(L, src) == LUA_OK &&
	       lua_pcall(L, 0, 1, 0) == LUA_OK && lua_istable(L, -1);
}
#endif /* WITH_LUA */

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - defaults, argv parsing and validation cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(conf_default_has_expected_values)
{
	const struct config conf = conf_default();

	T_EXPECT_EQ(conf.loglevel, LOG_LEVEL_NOTICE);
	T_EXPECT_EQ(conf.resolve_pf, PF_UNSPEC);
	T_EXPECT_EQ(conf.timeout, 60.0);
	T_EXPECT(conf.tcp_nodelay);
	T_EXPECT(conf.tcp_keepalive);
	T_EXPECT(conf.block_multicast);
	T_EXPECT_EQ(conf.startup_limit_rate, 30);
#if WITH_THREADS
	T_EXPECT_EQ(conf.workers, 1);
#endif
}

T_DECLARE_CASE(conf_requires_listen)
{
	struct config conf = conf_default();

	conf.listen = NULL;
	T_EXPECT(!conf_check(&conf));
	conf.http_listen = "127.0.0.1:8080";
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_incompatible_modes)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:8080";
	conf.http_listen = "127.0.0.1:8081";
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_timeout_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.timeout = 4.9;
	T_EXPECT(!conf_check(&conf));
	conf.timeout = 86400.1;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_loglevel_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.loglevel = LOG_LEVEL_SILENCE - 1;
	T_EXPECT(!conf_check(&conf));
	conf.loglevel = LOG_LEVEL_VERYVERBOSE + 1;
	T_EXPECT(!conf_check(&conf));
	conf.loglevel = LOG_LEVEL_NOTICE;
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_startup_limits_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.startup_limit_start = 4;
	conf.startup_limit_full = 3;
	T_EXPECT(!conf_check(&conf));

	conf = make_valid_conf();
	conf.startup_limit_rate = 101;
	T_EXPECT(!conf_check(&conf));

	/* startup_limit_full must not exceed a positive max_sessions */
	conf = make_valid_conf();
	conf.max_sessions = 100;
	conf.startup_limit_start = 1;
	conf.startup_limit_full = 200;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_accepts_unlimited_startup_full)
{
	struct config conf = make_valid_conf();

	/* startup_limit_full == 0 is the "unlimited" sentinel; a positive
	 * start must still validate (regression for the missing 0-sentinel
	 * handling in the startup_limit_start upper-bound check). */
	conf.startup_limit_start = 5;
	conf.startup_limit_rate = 10;
	conf.startup_limit_full = 0;
	T_EXPECT(conf_check(&conf));
}

#if WITH_THREADS
/*
 * Regression: workers was bounded only by INT_MAX, which is meaningless for a
 * thread count and lets `nworkers * sizeof(struct xfer_worker)' wrap a 32-bit
 * size_t in transfer_create().
 */
T_DECLARE_CASE(conf_rejects_workers_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.workers = 0;
	T_EXPECT(!conf_check(&conf));
	conf.workers = 1;
	T_EXPECT(conf_check(&conf));
	conf.workers = 1024;
	T_EXPECT(conf_check(&conf));
	conf.workers = 1025;
	T_EXPECT(!conf_check(&conf));
	conf.workers = INT_MAX;
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_THREADS */

T_DECLARE_CASE(parseargs_accepts_unlimited_max_startups)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--max-startups",
			 "5:10:0" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_EQ(conf.startup_limit_start, 5);
	T_EXPECT_EQ(conf.startup_limit_rate, 10);
	T_EXPECT_EQ(conf.startup_limit_full, 0);
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(parseargs_rejects_empty_numeric_args)
{
	/* strtoumax/strtod consume no digits on these; the parsers must not
	 * silently accept them as 0. */
	static const char *const cases[][2] = {
		{ "--loglevel", "" },
		{ "-m", "" },
		{ "-t", "" },
		{ "--max-startups", ":5:10" },
		{ "--max-startups", "5::10" },
	};
	for (size_t k = 0; k < ARRAY_SIZE(cases); k++) {
		struct config conf = conf_default();
		char *argv[] = { "conf_test", (char *)cases[k][0],
				 (char *)cases[k][1] };
		T_EXPECT(!conf_parseargs(&conf, 3, argv));
	}
}

T_DECLARE_CASE(parseargs_rejects_wrapped_negative_integers)
{
	char negative[64];
	(void)snprintf(negative, sizeof(negative), "-%" PRIuMAX, UINTMAX_MAX);
	char spaced[80];
	(void)snprintf(spaced, sizeof(spaced), " \t%s", negative);
	char startup[96];
	(void)snprintf(startup, sizeof(startup), "1:%s:10", negative);
	char startup_full[96];
	(void)snprintf(startup_full, sizeof(startup_full), "1:30:%s", negative);
	const char *const cases[][2] = {
		{ "-m", negative },
		{ "-m", spaced },
		{ "--loglevel", negative },
		{ "--max-startups", negative },
		{ "--max-startups", startup },
		{ "--max-startups", startup_full },
#if WITH_THREADS
		{ "--workers", spaced },
#endif
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct config conf;
		char *argv[] = { "conf_test", (char *)cases[i][0],
				 (char *)cases[i][1] };
		T_EXPECT(!conf_parseargs(&conf, 3, argv));
	}
	struct config conf;
	char *argv[] = { "conf_test", "-m", " \t+123", "--max-startups",
			 " +1: +30: +100" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_EQ(conf.max_sessions, 123);
	T_EXPECT_EQ(conf.startup_limit_start, 1);
	T_EXPECT_EQ(conf.startup_limit_rate, 30);
	T_EXPECT_EQ(conf.startup_limit_full, 100);
}

T_DECLARE_CASE(conf_rejects_proxy_with_socks5_extensions)
{
	struct config conf = make_valid_conf();

	conf.proxy = "socks5://127.0.0.1:1080";
	conf.socks5_bind = true;
	T_EXPECT(!conf_check(&conf));

	conf = make_valid_conf();
	conf.proxy = "socks5://127.0.0.1:1080";
	conf.socks5_udp = true;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_accepts_valid_configuration)
{
	struct config conf = make_valid_conf();

	conf.max_sessions = 1024;
	conf.startup_limit_start = 64;
	conf.startup_limit_rate = 25;
	conf.startup_limit_full = 128;
	conf.tcp_sndbuf = 32768;
	conf.tcp_rcvbuf = 32768;
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_invalid_resolve_pf)
{
	struct config conf = make_valid_conf();

	conf.resolve_pf = -1;
	T_EXPECT(!conf_check(&conf));

	conf.resolve_pf = PF_UNSPEC;
	T_EXPECT(conf_check(&conf));
	conf.resolve_pf = PF_INET;
	T_EXPECT(conf_check(&conf));
	conf.resolve_pf = PF_INET6;
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_negative_max_sessions)
{
	struct config conf = make_valid_conf();

	conf.max_sessions = -1;
	T_EXPECT(!conf_check(&conf));
	conf.max_sessions = 0;
	T_EXPECT(conf_check(&conf));
}

#if WITH_LUA
/*
 * Regression: an unpadded \7 escape immediately followed by a literal
 * ASCII digit re-parses under Lua's greedy \ddd decimal escape as a
 * single, different byte -- \007 (still one control byte) prevents that.
 */
T_DECLARE_CASE(conf_print_round_trips_control_char_before_digit)
{
	struct config conf = make_valid_conf();
	conf.listen = "\x07"
		      "1.2.3.4:1080";

	char *const out = capture_conf_print(_t_, &conf);
	T_CHECK(out != NULL);

	lua_State *restrict L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	T_CHECK(load_printed_conf(L, out));

	lua_getfield(L, -1, "listen");
	T_CHECK(lua_isstring(L, -1));
	size_t len;
	const char *const listen = lua_tolstring(L, -1, &len);
	T_EXPECT_EQ(len, strlen(conf.listen));
	T_EXPECT_MEMEQ(listen, conf.listen, len);

	close_test_lua(L);
}

/*
 * Regression: %g's default 6 significant digits truncates timeout on a
 * --dump-config round trip; %.17g always recovers the exact double.
 *
 * Gated to a 64-bit lua_Number: on a LUA_32BITS build lua_Number is float,
 * so the reload through Lua narrows the printed double to float precision and
 * an exact round trip is impossible by construction. The %.17g print itself
 * (the actual regression guard) is width-independent.
 */
#if !LUA_32BITS
T_DECLARE_CASE(conf_print_round_trips_double_precision)
{
	struct config conf = make_valid_conf();
	conf.timeout = 1.0 / 3.0;

	char *const out = capture_conf_print(_t_, &conf);
	T_CHECK(out != NULL);

	lua_State *restrict L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	T_CHECK(load_printed_conf(L, out));

	lua_getfield(L, -1, "timeout");
	T_CHECK(lua_isnumber(L, -1));
	T_EXPECT(lua_tonumber(L, -1) == conf.timeout);

	close_test_lua(L);
}
#endif /* !LUA_32BITS */

/* Read `path` whole into `buf` as a NUL-terminated string. Returns false on an
 * I/O error or when the file does not fit. */
static bool read_wholefile(
	char *restrict buf, const size_t bufsize, const char *restrict path)
{
	FILE *const f = fopen(path, "rb");
	if (f == NULL) {
		return false;
	}
	const size_t n = fread(buf, 1, bufsize - 1, f);
	const bool ok = (ferror(f) == 0 && feof(f) != 0);
	(void)fclose(f);
	buf[n] = '\0';
	return ok;
}

/*
 * Regression: conf_print checked every write but never the final flush. A
 * redirected `--dump-config' is fully buffered and the whole dump fits in one
 * stdio buffer, so nothing had reached the file when conf_print reported
 * success -- and every write error surfaced at the unchecked flush instead.
 */
T_DECLARE_CASE(conf_print_flushes_the_dump)
{
	char path[] = TEST_TMPDIR "/conf_test_XXXXXX";
	const int fd = mkstemp(path);
	T_CHECK(fd >= 0);
	T_CHECK(close(fd) == 0);
	const int saved = dup(STDOUT_FILENO);
	T_CHECK(saved >= 0);

	const struct config conf = make_valid_conf();
	/* freopen re-associates stdout with a regular file, which POSIX makes
	 * fully buffered; no testing macro may run before stdout is restored */
	char dumped[4096] = "";
	bool ok = false, samefd = false, read_ok = false;
	if (freopen(path, "w", stdout) != NULL) {
		samefd = (fileno(stdout) == STDOUT_FILENO);
		ok = conf_print(&conf);
		read_ok = read_wholefile(dumped, sizeof(dumped), path);
		(void)fflush(stdout);
	}
	(void)dup2(saved, STDOUT_FILENO);
	(void)close(saved);
	(void)unlink(path);

	T_CHECK(samefd);
	T_CHECK(read_ok);
	T_EXPECT(ok);
	/* the whole dump is on the file, not still in the stdio buffer */
	T_EXPECT(strncmp(dumped, "return {\n", 9) == 0);
	T_EXPECT(strstr(dumped, "\n}\n") != NULL);
}

T_DECLARE_CASE(conf_pushfield_matches_snapshot)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	lua_State *restrict L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	conf_pushtable(L, &conf);
	lua_pushnil(L);
	while (lua_next(L, 1) != 0) {
		const char *const key = lua_tostring(L, -2);
		conf_pushfield(L, &conf, key);
		T_EXPECT(lua_rawequal(L, -1, -2));
		lua_pop(L, 2);
	}
	conf_pushfield(L, &conf, "proxy");
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 1);
	conf_pushfield(L, &conf, "missing");
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 1);
	conf.loglevel = LOG_LEVEL_DEBUG;
	conf_pushfield(L, &conf, "loglevel");
	T_EXPECT_EQ(lua_tointeger(L, -1), LOG_LEVEL_DEBUG);
}

/*
 * conf_fields[] is the single source of truth shared by conf_print and
 * conf_loadfromtable, and a dump is meant to load back through `-c'. A wrong
 * offsetof or conf_type in an entry passes every other case in this file, so
 * round trip every field at once with a distinct value each.
 */
T_DECLARE_CASE(conf_print_round_trips_every_field)
{
	struct config conf = conf_default();
	conf.listen = "0.0.0.0:1080";
	conf.forward = "127.0.0.1:8080";
	conf.proxy = "socks5://127.0.0.2:1081";
	conf.restapi = "127.0.0.3:9080";
	conf.http_listen = "127.0.0.4:8081";
#if WITH_CARES
	conf.nameserver = "127.0.0.53:53";
#endif
#if WITH_NETDEVICE
	conf.netdev = "eth0";
#endif
	conf.loglevel = LOG_LEVEL_DEBUG;
	conf.resolve_pf = PF_INET6;
	conf.timeout = 123.5;
#if WITH_RULESET
	conf.memlimit = 64;
	conf.auth_required = true;
#endif
#if WITH_SPLICE
	conf.pipe = true;
#endif
#if WITH_REUSEPORT
	conf.reuseport = true;
#endif
#if WITH_TCP_FASTOPEN
	conf.tcp_fastopen = false;
#endif
#if WITH_TCP_FASTOPEN_CONNECT
	conf.tcp_fastopen_connect = true;
#endif
	conf.tcp_nodelay = false;
	conf.tcp_keepalive = false;
#if WITH_TPROXY
	conf.transparent = true;
#endif
#if WITH_RULESET
	conf.traceback = true;
#endif
	conf.socks5_bind = true;
	conf.socks5_udp = true;
	conf.block_loopback = true;
	conf.block_multicast = false;
	conf.block_local = true;
	conf.block_global = true;
	conf.tcp_sndbuf = 32768;
	conf.tcp_rcvbuf = 65536;
#if WITH_TCP_KEEPALIVE_PARAMS
	conf.tcp_keepidle = 111;
	conf.tcp_keepintvl = 22;
	conf.tcp_keepcnt = 33;
#endif
	conf.max_sessions = 4096;
	conf.startup_limit_start = 12;
	conf.startup_limit_rate = 34;
	conf.startup_limit_full = 56;
#if WITH_THREADS
	conf.workers = 7;
#endif

	char *const out = capture_conf_print(_t_, &conf);
	T_CHECK(out != NULL);
	lua_State *restrict L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	T_CHECK(load_printed_conf(L, out));

	struct config *loaded = new_config(_t_, conf_default());
	T_EXPECT(conf_loadfromtable(L, loaded));
	conf_pushtable(L, &conf);
	bool matches = true;
	lua_pushnil(L);
	while (lua_next(L, 1) != 0) {
		lua_pushvalue(L, -2);
		lua_gettable(L, 2);
		matches = matches && lua_rawequal(L, -1, -2);
		lua_pop(L, 2);
	}
	close_test_lua(L);
	T_EXPECT(matches);

	T_EXPECT_STREQ(loaded->listen, conf.listen);
	T_EXPECT_STREQ(loaded->forward, conf.forward);
	T_EXPECT_STREQ(loaded->proxy, conf.proxy);
	T_EXPECT_STREQ(loaded->restapi, conf.restapi);
	T_EXPECT_STREQ(loaded->http_listen, conf.http_listen);
#if WITH_CARES
	T_EXPECT_STREQ(loaded->nameserver, conf.nameserver);
#endif
#if WITH_NETDEVICE
	T_EXPECT_STREQ(loaded->netdev, conf.netdev);
#endif
	T_EXPECT_EQ(loaded->loglevel, conf.loglevel);
	T_EXPECT_EQ(loaded->resolve_pf, conf.resolve_pf);
	T_EXPECT(loaded->timeout == conf.timeout);
#if WITH_RULESET
	T_EXPECT_EQ(loaded->memlimit, conf.memlimit);
	T_EXPECT_EQ(loaded->auth_required, conf.auth_required);
#endif
#if WITH_SPLICE
	T_EXPECT_EQ(loaded->pipe, conf.pipe);
#endif
#if WITH_REUSEPORT
	T_EXPECT_EQ(loaded->reuseport, conf.reuseport);
#endif
#if WITH_TCP_FASTOPEN
	T_EXPECT_EQ(loaded->tcp_fastopen, conf.tcp_fastopen);
#endif
#if WITH_TCP_FASTOPEN_CONNECT
	T_EXPECT_EQ(loaded->tcp_fastopen_connect, conf.tcp_fastopen_connect);
#endif
	T_EXPECT_EQ(loaded->tcp_nodelay, conf.tcp_nodelay);
	T_EXPECT_EQ(loaded->tcp_keepalive, conf.tcp_keepalive);
#if WITH_TPROXY
	T_EXPECT_EQ(loaded->transparent, conf.transparent);
#endif
#if WITH_RULESET
	T_EXPECT_EQ(loaded->traceback, conf.traceback);
#endif
	T_EXPECT_EQ(loaded->socks5_bind, conf.socks5_bind);
	T_EXPECT_EQ(loaded->socks5_udp, conf.socks5_udp);
	T_EXPECT_EQ(loaded->block_loopback, conf.block_loopback);
	T_EXPECT_EQ(loaded->block_multicast, conf.block_multicast);
	T_EXPECT_EQ(loaded->block_local, conf.block_local);
	T_EXPECT_EQ(loaded->block_global, conf.block_global);
	T_EXPECT_EQ(loaded->tcp_sndbuf, conf.tcp_sndbuf);
	T_EXPECT_EQ(loaded->tcp_rcvbuf, conf.tcp_rcvbuf);
#if WITH_TCP_KEEPALIVE_PARAMS
	T_EXPECT_EQ(loaded->tcp_keepidle, conf.tcp_keepidle);
	T_EXPECT_EQ(loaded->tcp_keepintvl, conf.tcp_keepintvl);
	T_EXPECT_EQ(loaded->tcp_keepcnt, conf.tcp_keepcnt);
#endif
	T_EXPECT_EQ(loaded->max_sessions, conf.max_sessions);
	T_EXPECT_EQ(loaded->startup_limit_start, conf.startup_limit_start);
	T_EXPECT_EQ(loaded->startup_limit_rate, conf.startup_limit_rate);
	T_EXPECT_EQ(loaded->startup_limit_full, conf.startup_limit_full);
#if WITH_THREADS
	T_EXPECT_EQ(loaded->workers, conf.workers);
#endif

	clear_config(loaded);
}

static int loadfromtable_body(lua_State *restrict L);

/* Stateful fields are evaluated once, even when another lookup would change
 * type or raise. Scalars and strings commit from the same snapshot. */
T_DECLARE_CASE(conf_loadfromtable_reads_scalar_once)
{
	struct config *conf = new_config(_t_, make_valid_conf());
	lua_State *L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	luaL_openlibs(L);
	T_CHECK(load_printed_conf(
		L,
		"local n = 0 "
		"return setmetatable({listen='127.0.0.1:1080', loglevel=7}, "
		"{__index=function(_,k) if k=='max_sessions' then "
		"n=n+1 if n==1 then return 100 end error('read twice') end end})"));
	const int top = lua_gettop(L);
	T_EXPECT(conf_loadfromtable(L, conf));
	T_EXPECT_EQ(lua_gettop(L), top);
	T_EXPECT_EQ(conf->loglevel, 7);
	T_EXPECT_EQ(conf->max_sessions, 100);
	clear_config(conf);
	close_test_lua(L);
}

T_DECLARE_CASE(conf_loadfromtable_raise_leaves_config_unchanged)
{
	struct config conf = make_valid_conf();
	conf.loglevel = 2;
	conf.max_sessions = 42;
	lua_State *L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	luaL_openlibs(L);
	T_CHECK(load_printed_conf(
		L,
		"return setmetatable({listen='127.0.0.1:1080', loglevel=7}, "
		"{__index=function(_,k) if k=='max_sessions' then error('boom') end end})"));
	lua_pushcfunction(L, loadfromtable_body);
	lua_insert(L, -2);
	lua_pushlightuserdata(L, &conf);
	T_EXPECT(lua_pcall(L, 2, 1, 0) != LUA_OK);
	T_EXPECT_EQ(conf.loglevel, 2);
	T_EXPECT_EQ(conf.max_sessions, 42);
	T_EXPECT(conf.strings == NULL);
	close_test_lua(L);
}
#endif /* WITH_LUA */

T_DECLARE_CASE(conf_warns_small_tcp_buffers)
{
	struct config conf = make_valid_conf();

	conf.tcp_sndbuf = 1024;
	conf.tcp_rcvbuf = 4096;
	T_EXPECT(conf_check(&conf)); /* warns but remains valid */
}

#if WITH_TCP_KEEPALIVE_PARAMS
T_DECLARE_CASE(conf_default_keeps_system_keepalive_timing)
{
	const struct config conf = conf_default();

	T_EXPECT_EQ(conf.tcp_keepidle, 0);
	T_EXPECT_EQ(conf.tcp_keepintvl, 0);
	T_EXPECT_EQ(conf.tcp_keepcnt, 0);
}

T_DECLARE_CASE(conf_rejects_keepalive_timing_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.tcp_keepidle = 32768;
	T_EXPECT(!conf_check(&conf));
	conf.tcp_keepidle = 32767;
	T_EXPECT(conf_check(&conf));

	conf.tcp_keepintvl = -1;
	T_EXPECT(!conf_check(&conf));
	conf.tcp_keepintvl = 30;
	T_EXPECT(conf_check(&conf));

	conf.tcp_keepcnt = 128;
	T_EXPECT(!conf_check(&conf));
	conf.tcp_keepcnt = 127;
	T_EXPECT(conf_check(&conf));
}

/* Timing without keepalive is inert; conf_check warns but stays valid. */
T_DECLARE_CASE(conf_warns_keepalive_timing_without_keepalive)
{
	struct config conf = make_valid_conf();

	conf.tcp_keepalive = false;
	conf.tcp_keepidle = 600;
	T_EXPECT(conf_check(&conf));
}
#endif /* WITH_TCP_KEEPALIVE_PARAMS */

T_DECLARE_CASE(conf_rejects_block_global_and_local)
{
	struct config conf = make_valid_conf();

	conf.block_global = true;
	conf.block_local = true;
	T_EXPECT(!conf_check(&conf));
}

#if WITH_TPROXY
T_DECLARE_CASE(conf_rejects_http_with_tproxy)
{
	struct config conf = make_valid_conf();

	conf.http_listen = "127.0.0.1:8080";
	conf.transparent = true;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_forward_with_tproxy)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:9999";
	conf.transparent = true;
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_TPROXY */

struct advise_args {
	const struct config *conf;
	bool has_ruleset;
};

static bool run_conf_advise(const void *data)
{
	const struct advise_args *restrict args = data;
	conf_advise(args->conf, args->has_ruleset);
	return true;
}

/* Capture conf_advise() output in a fixture-owned buffer; returns NULL on
 * failure. slog is pointed at stderr through
 * conf.c's cached writer, then left fd-free again so a later fd capture is not
 * corrupted (see parseargs_log_outputs). */
static char *capture_conf_advise(
	struct testing_ctx *_t_, const struct config *restrict conf,
	const bool has_ruleset)
{
	struct config logconf = conf_default();
	char *logargv[] = { "conf_test", "-l", "127.0.0.1:1080", "--log",
			    "stderr" };
	if (!conf_parseargs(&logconf, (int)ARRAY_SIZE(logargv), logargv)) {
		return NULL;
	}
	const struct advise_args args = {
		.conf = conf,
		.has_ruleset = has_ruleset,
	};
	char *const out =
		capture_fd(_t_, STDERR_FILENO, run_conf_advise, &args);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
	return out;
}

/*
 * Regression: this notice once lived in conf_check() and claimed the ruleset
 * would overwrite the proxy chain. aux_todialreq() dials on
 * dialreq_new(basereq, ...), which copies the -x hops first and appends the
 * ruleset's proxies, so -x always stays in the path.
 */
T_DECLARE_CASE(conf_advise_notes_ruleset_extends_proxy)
{
	struct config conf = make_valid_conf();
	conf.proxy = "socks5://127.0.0.1:1080";

	char *const out = capture_conf_advise(_t_, &conf, true);
	T_CHECK(out != NULL);

	T_EXPECT(strstr(out, "overwritten") == NULL);
	T_EXPECT(strstr(out, "extends the `-x' proxy chain") != NULL);
}

/*
 * Regression: the notice keys on whether a ruleset was installed, not on the
 * -r filename conf_check() used to test -- a -c boot config installs one while
 * leaving that field NULL, and an -r file may install none.
 */
T_DECLARE_CASE(conf_advise_silent_without_ruleset_or_proxy)
{
	struct config conf = make_valid_conf();
	conf.proxy = "socks5://127.0.0.1:1080";

	char *const noruleset = capture_conf_advise(_t_, &conf, false);
	T_CHECK(noruleset != NULL);
	T_EXPECT(strstr(noruleset, "proxy chain") == NULL);

	/* a ruleset with no chain in front of it has nothing to extend */
	conf.proxy = NULL;
	char *const noproxy = capture_conf_advise(_t_, &conf, true);
	T_CHECK(noproxy != NULL);
	T_EXPECT(strstr(noproxy, "proxy chain") == NULL);
}

/*
 * CONF_FORWARD_ANY names no destination, so a ruleset has to choose one per
 * connection; on its own it dials the wildcard and every forwarded connection
 * fails. That is a valid-but-useless combination conf_check() cannot see, since
 * a `-c' boot config installs a ruleset without setting the `-r' field.
 */
T_DECLARE_CASE(conf_advise_notes_forward_placeholder_without_ruleset)
{
	struct config conf = make_valid_conf();
	conf.forward = CONF_FORWARD_ANY;

	char *const noruleset = capture_conf_advise(_t_, &conf, false);
	T_CHECK(noruleset != NULL);
	T_EXPECT(strstr(noruleset, "names no destination") != NULL);

	char *const withruleset = capture_conf_advise(_t_, &conf, true);
	T_CHECK(withruleset != NULL);
	T_EXPECT(strstr(withruleset, "names no destination") == NULL);

	/* a named destination needs no ruleset to reach */
	conf.forward = "127.0.0.1:8080";
	char *const fixed = capture_conf_advise(_t_, &conf, false);
	T_CHECK(fixed != NULL);
	T_EXPECT(strstr(fixed, "names no destination") == NULL);
}

#if WITH_RULESET
T_DECLARE_CASE(conf_rejects_ruleset_with_socks5_bind)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.socks5_bind = true;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(conf_rejects_ruleset_with_socks5_udp)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.socks5_udp = true;
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_RULESET */

T_DECLARE_CASE(conf_rejects_auth_required_in_forward_mode)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:8080";
	conf.auth_required = true;
	T_EXPECT(!conf_check(&conf));
}

#if WITH_RULESET
T_DECLARE_CASE(conf_defers_auth_required_ruleset_check)
{
	struct config conf = make_valid_conf();

	conf.auth_required = true;
	/* the ruleset requirement is enforced in main(), not conf_check();
	 * SOCKS mode supports authentication, so this passes */
	T_EXPECT(conf_check(&conf));
}
#endif /* WITH_RULESET */

/* conf_parseargs tests */

T_DECLARE_CASE(parseargs_help_returns_false)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "--help" };

	T_EXPECT(!conf_parseargs(&conf, 2, argv));
}

static bool run_help(const void *data)
{
	(void)data;
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "--help" };
	(void)conf_parseargs(&conf, 2, argv);
	return true;
}

/* Capture --help output in a fixture-owned buffer; returns NULL on failure. */
static char *capture_help_text(struct testing_ctx *_t_)
{
	return capture_fd(_t_, STDERR_FILENO, run_help, NULL);
}

/*
 * Regression: every conditional flag's help-text gate must match its
 * parsing gate. -c/--config's help line was once bundled under WITH_LUA
 * while its parsing was gated on the stricter WITH_RULESET, so a
 * WITH_LUA-but-not-WITH_RULESET build advertised a flag that
 * conf_parseargs then rejected as unknown; both gates now match at
 * WITH_LUA. Written to hold under whichever of the (three valid)
 * WITH_LUA/WITH_RULESET combinations this binary was built with, so it
 * stays meaningful across the project's whole build matrix instead of
 * just the default configuration.
 */
T_DECLARE_CASE(parseargs_help_gate_matches_config_flag_parsing)
{
	char *const help = capture_help_text(_t_);
	T_CHECK(help != NULL);

#if WITH_LUA
	T_EXPECT(strstr(help, "-c, --config") != NULL);
	T_EXPECT(strstr(help, "--dump-config") != NULL);
#else
	T_EXPECT(strstr(help, "-c, --config") == NULL);
	T_EXPECT(strstr(help, "--dump-config") == NULL);
#endif
#if WITH_RULESET
	T_EXPECT(strstr(help, "--auth-required") != NULL);
#else
	T_EXPECT(strstr(help, "--auth-required") == NULL);
#endif
}

T_DECLARE_CASE(parseargs_resolve_pf_flags)
{
	struct config conf = conf_default();
	char *argv4[] = { "conf_test", "-4", "-l", "127.0.0.1:1080" };

	T_EXPECT(conf_parseargs(&conf, 4, argv4));
	T_EXPECT_EQ(conf.resolve_pf, PF_INET);

	char *argv6[] = { "conf_test", "-6", "-l", "127.0.0.1:1080" };
	T_EXPECT(conf_parseargs(&conf, 4, argv6));
	T_EXPECT_EQ(conf.resolve_pf, PF_INET6);
}

T_DECLARE_CASE(parseargs_http_with_address)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "0.0.0.0:1080", "--http",
			 "0.0.0.0:8080" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.http_listen, "0.0.0.0:8080");
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:1080");
}

T_DECLARE_CASE(parseargs_http_only)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "0.0.0.0:8080", "--http" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.listen == NULL);
	T_EXPECT_STREQ(conf.http_listen, "0.0.0.0:8080");
}

/* --http immediately followed by another option must not consume it as an
 * address (the argv[i+1][0] == '-' branch): http_listen falls back to the -l
 * address and the following option is still parsed. */
T_DECLARE_CASE(parseargs_http_followed_by_option)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--http", "-4" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT(conf.listen == NULL);
	T_EXPECT_STREQ(conf.http_listen, "127.0.0.1:1080");
	T_EXPECT_EQ(conf.resolve_pf, PF_INET);
}

/* A bare --http takes over the -l address; with no -l it must fail the parse
 * rather than be dropped, or a boot config's `listen' later satisfies
 * conf_check() and the daemon serves SOCKS where HTTP was asked for. */
T_DECLARE_CASE(parseargs_http_only_requires_listen)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "--http" };
		T_EXPECT(!conf_parseargs(&conf, 2, argv));
	}
#if WITH_LUA
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-c", "boot.lua", "--http" };
		T_EXPECT(!conf_parseargs(&conf, 4, argv));
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "--http", "-c", "boot.lua" };
		T_EXPECT(!conf_parseargs(&conf, 4, argv));
	}
#endif /* WITH_LUA */
}

/* --fastopen-connect exists only in a WITH_TCP_FASTOPEN_CONNECT build; there it
 * sets the flag, and otherwise it is an unknown option that fails the parse. */
T_DECLARE_CASE(parseargs_fastopen_connect)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
			 "--fastopen-connect" };

#if WITH_TCP_FASTOPEN_CONNECT
	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.tcp_fastopen_connect);
#else
	T_EXPECT(!conf_parseargs(&conf, 4, argv));
#endif
}

T_DECLARE_CASE(parseargs_proxy_and_api)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test",
			 "-l",
			 "127.0.0.1:1080",
			 "-x",
			 "socks5://127.0.0.1:9090",
			 "--api",
			 "127.0.0.1:9080" };

	T_EXPECT(conf_parseargs(&conf, 7, argv));
	T_EXPECT_STREQ(conf.proxy, "socks5://127.0.0.1:9090");
	T_EXPECT_STREQ(conf.restapi, "127.0.0.1:9080");
}

T_DECLARE_CASE(parseargs_auth_required)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
			 "--auth-required" };

#if WITH_RULESET
	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.auth_required);
#else /* WITH_RULESET */
	/*
	 * Credentials are only ever verified by process_cb, which requires a
	 * ruleset; without one, --auth-required would be unenforceable
	 * negotiation theater, so a build without ruleset support must reject
	 * the flag outright.
	 */
	T_EXPECT(!conf_parseargs(&conf, 4, argv));
#endif /* WITH_RULESET */
}

T_DECLARE_CASE(parseargs_user_daemonize_color)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test",
			 "-l",
			 "127.0.0.1:1080",
			 "-u",
			 "nobody:nogroup",
			 "-d",
			 "--log",
			 "terminal",
			 "--enable-socks5-bind",
			 "--enable-socks5-udp" };

	T_EXPECT(conf_parseargs(&conf, 10, argv));
	T_EXPECT_STREQ(conf.user_name, "nobody:nogroup");
	T_EXPECT(conf.daemonize);
	T_EXPECT(conf.socks5_bind);
	T_EXPECT(conf.socks5_udp);

	/* --log terminal repointed the slog sink; leave it fd-free so a later
	 * fd capture is not corrupted (see parseargs_log_outputs) */
	slog_setoutput(SLOG_OUTPUT_DISCARD);
}

T_DECLARE_CASE(parseargs_timeout)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-t",
				 "30.5" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.timeout, 30.5);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-t",
				 "30x" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

T_DECLARE_CASE(parseargs_loglevel)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--loglevel", "3" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.loglevel, 3);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--loglevel", "bad" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

T_DECLARE_CASE(parseargs_block_outbound)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", "loopback" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT(conf.block_loopback);
		T_EXPECT(!conf.block_multicast);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", "local,global" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT(!conf.block_loopback);
		T_EXPECT(conf.block_local);
		T_EXPECT(conf.block_global);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", "invalid_token" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
	{
		/* argument longer than 255 chars is rejected */
		struct config conf = conf_default();
		char long_arg[300];
		memset(long_arg, 'x', sizeof(long_arg) - 1);
		long_arg[sizeof(long_arg) - 1] = '\0';
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", long_arg };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
	{
		/* empty elements -- leading, adjacent and trailing commas --
		 * are skipped rather than rejected as unknown class names */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", ",local,,global," };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT(conf.block_local);
		T_EXPECT(conf.block_global);
		T_EXPECT(!conf.block_loopback);
		T_EXPECT(!conf.block_multicast);
	}
	{
		/* an all-empty list clears every class */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--block-outbound", "" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT(!conf.block_loopback);
		T_EXPECT(!conf.block_multicast);
		T_EXPECT(!conf.block_local);
		T_EXPECT(!conf.block_global);
	}
}

T_DECLARE_CASE(parseargs_max_sessions)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-m",
				 "512" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.max_sessions, 512);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-m",
				 "bad" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

T_DECLARE_CASE(parseargs_max_startups)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--max-startups", "10:50:100" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.startup_limit_start, 10);
		T_EXPECT_EQ(conf.startup_limit_rate, 50);
		T_EXPECT_EQ(conf.startup_limit_full, 100);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--max-startups", "bad" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

T_DECLARE_CASE(parseargs_rejects_above_int_max_numeric)
{
	/* opt_parse_int rejects a syntactically valid decimal exceeding INT_MAX
	 * (the overflow half of its check, distinct from the missing-digit half);
	 * exercise it through each of its three consumers */
	static const char *const cases[][2] = {
		{ "-m", "9999999999" },
		{ "--loglevel", "9999999999" },
		{ "--max-startups", "9999999999:0:0" },
	};
	for (size_t k = 0; k < ARRAY_SIZE(cases); k++) {
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 (char *)cases[k][0], (char *)cases[k][1] };
		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

/* opt_parse_int() and strtoimax() leave the terminator to the caller, so each
 * consumer's own check is what rejects the rest of the argument instead of
 * accepting a truncated number (`-m 5x' as 5) */
T_DECLARE_CASE(parseargs_rejects_numeric_trailing_junk)
{
	static const char *const cases[][2] = {
		{ "-m", "5x" },
		{ "--loglevel", "3x" },
		{ "--max-startups", "10;50:100" },
		{ "--max-startups", "10:50" },
		{ "--max-startups", "10:50:100x" },
#if WITH_THREADS
		{ "--workers", "4x" },
#endif /* WITH_THREADS */
#if WITH_RULESET
		{ "--memlimit", "12x" },
#endif /* WITH_RULESET */
	};
	for (size_t k = 0; k < ARRAY_SIZE(cases); k++) {
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 (char *)cases[k][0], (char *)cases[k][1] };
		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}

T_DECLARE_CASE(parseargs_double_dash_and_unknown)
{
	{
		/* -- terminates option parsing; remaining args are ignored */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--",
				 "--unknown" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
	}
	{
		/* unknown argument */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "--unknown-flag-xyz" };

		T_EXPECT(!conf_parseargs(&conf, 2, argv));
	}
	{
		/* missing argument for option */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l" };

		T_EXPECT(!conf_parseargs(&conf, 2, argv));
	}
}

T_DECLARE_CASE(parseargs_log_outputs)
{
	static const char *const sinks[] = { "stdout", "stderr", "syslog",
					     "discard" };
	for (size_t i = 0; i < ARRAY_SIZE(sinks); i++) {
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--log",
				 (char *)sinks[i] };
		T_EXPECT(conf_parseargs(&conf, 5, argv));
	}
	{
		/* unknown --log sink is rejected */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--log",
				 "nowhere" };
		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
	/* The cases above repointed the process-global slog sink at stdout/
	 * stderr; a later test that captures fd 1 or 2 (capture_fd) would then
	 * catch stray log lines. Leave the sink fd-free so the suite stays
	 * order-independent. */
	slog_setoutput(SLOG_OUTPUT_DISCARD);
}

#if WITH_LUA
T_DECLARE_CASE(parseargs_dump_config)
{
	/* --dump-config sets the dump flag for deferred handling in main */
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--dump-config" };
	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.dump_config);
}
#endif /* WITH_LUA */

#if WITH_CARES
T_DECLARE_CASE(parseargs_nameserver)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--nameserver",
			 "8.8.8.8" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.nameserver, "8.8.8.8");
}
#endif /* WITH_CARES */

#if WITH_TPROXY
T_DECLARE_CASE(parseargs_tproxy)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--tproxy" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.transparent);
}
#endif /* WITH_TPROXY */

#if WITH_NETDEVICE
T_DECLARE_CASE(parseargs_netdev)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-i", "eth0" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.netdev, "eth0");
}
#endif /* WITH_NETDEVICE */

#if WITH_REUSEPORT
T_DECLARE_CASE(parseargs_reuseport)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--reuseport" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.reuseport);
}
#endif /* WITH_REUSEPORT */

/*
 * Regression for the hardcoded I/O worker count: main() passed a literal 1 to
 * transfer_create() and nothing could change it, so transfer.c's multi-worker
 * engine was unreachable in every build. --workers (and the matching `workers`
 * boot-config key) now set it. The option exists only in a WITH_THREADS build,
 * where the engine runs worker threads; without threads transfers run on the
 * main loop, so the count is meaningless and the flag is simply unknown.
 */
#if WITH_THREADS
T_DECLARE_CASE(parseargs_workers)
{
	{
		/* a valid count parses and passes validation */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--workers", "4" };
		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.workers, 4);
		T_EXPECT(conf_check(&conf));
	}
	{
		/* zero is rejected: transfer_serve() distributes with `% workers` */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--workers", "0" };
		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.workers, 0);
		T_EXPECT(!conf_check(&conf));
	}
	{
		/* a non-numeric argument fails the parse */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--workers", "bad" };
		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}
#else /* WITH_THREADS */
T_DECLARE_CASE(parseargs_workers)
{
	/* without thread support --workers is an unknown option */
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--workers",
			 "4" };
	T_EXPECT(!conf_parseargs(&conf, 5, argv));
}
#endif /* WITH_THREADS */

#if WITH_SPLICE
T_DECLARE_CASE(parseargs_pipe)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--pipe" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.pipe);
}
#endif /* WITH_SPLICE */

#if WITH_TCP_FASTOPEN
T_DECLARE_CASE(parseargs_no_fastopen)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--no-fastopen" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(!conf.tcp_fastopen);
}
#endif /* WITH_TCP_FASTOPEN */

#if WITH_RULESET
T_DECLARE_CASE(parseargs_ruleset)
{
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l",	     "127.0.0.1:1080",
				 "-r",	      "ruleset.lua", "--traceback" };

		T_EXPECT(conf_parseargs(&conf, 6, argv));
		T_EXPECT_STREQ(conf.ruleset, "ruleset.lua");
		T_EXPECT(conf.traceback);
	}
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--memlimit", "256" };

		T_EXPECT(conf_parseargs(&conf, 5, argv));
		T_EXPECT_EQ(conf.memlimit, 256);
	}
	{
		/* memlimit overflow */
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
				 "--memlimit", "9999999999" };

		T_EXPECT(!conf_parseargs(&conf, 5, argv));
	}
}
#endif /* WITH_RULESET */

T_DECLARE_CASE(parseargs_forward_flag)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-f",
			 "127.0.0.1:8080" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT(
		conf.forward != NULL &&
		strcmp(conf.forward, "127.0.0.1:8080") == 0);
}

T_DECLARE_CASE(parseargs_block_multicast_token)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
			 "--block-outbound", "multicast" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT(conf.block_multicast);
	T_EXPECT(!conf.block_loopback);
}

#if WITH_LUA
T_DECLARE_CASE(parseargs_config_flag)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-c",
			 "boot.lua" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT(conf.boot != NULL && strcmp(conf.boot, "boot.lua") == 0);
}
#endif /* WITH_LUA */

#if WITH_RULESET
T_DECLARE_CASE(parseargs_config_and_ruleset_mutually_exclusive)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-c",
			 "boot.lua",  "-r", "ruleset.lua" };
	T_EXPECT(!conf_parseargs(&conf, 7, argv));
}

T_DECLARE_CASE(parseargs_memlimit_negative_clamped)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--memlimit",
			 "-5" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_EQ(conf.memlimit, 0);
}
#endif /* WITH_RULESET */

#if WITH_LUA
/* conf_loadfromtable tests */

static lua_State *new_conf_table(struct testing_ctx *_t_)
{
	lua_State *L = new_test_lua(_t_);
	if (L == NULL) {
		return NULL;
	}
	lua_newtable(L);
	return L;
}

/* Fake the sizing inputs and fail any resulting allocation, so boundary
 * checks need no large strings or allocations. */
T_DECLARE_SUBCASE(
	expect_string_size_failure, const size_t *lengths, const size_t count,
	const size_t allocations, const size_t allocation_size,
	const bool reload)
{
	lua_State *const L = new_conf_table(_t_);
	T_CHECK(L != NULL);
	char *const original = malloc(4);
	if (original == NULL) {
		close_test_lua(L);
		T_CHECK(original != NULL);
		return;
	}
	memcpy(original, "old", 4);
	struct config *conf = new_config(_t_, make_valid_conf());
	conf->strings = original;
	conf->listen = original;
	if (count > 1) {
		lua_pushliteral(L, "");
		lua_setfield(L, -2, "proxy");
	}
	lua_pushinteger(L, 7);
	lua_setfield(L, -2, "loglevel");
	const int top = lua_gettop(L);
	mock_string_lengths = lengths;
	mock_string_count = count;
	mock_string_index = 0;
	mock_alloc_count = 0;
	mock_alloc_size = 0;
	const bool ok = reload ? conf_reloadfromtable(L, conf, false) :
				 conf_loadfromtable(L, conf);
	mock_string_lengths = NULL;
	const bool unchanged =
		conf->strings == original && conf->listen == original &&
		conf->proxy == NULL && conf->loglevel == LOG_LEVEL_NOTICE;
	const int final_top = lua_gettop(L);
	clear_config(conf);
	close_test_lua(L);

	T_EXPECT(!ok);
	T_EXPECT(unchanged);
	T_EXPECT_EQ(final_top, top);
	T_EXPECT_EQ(mock_string_index, count);
	T_EXPECT_EQ(mock_alloc_count, allocations);
	T_EXPECT_EQ(mock_alloc_size, allocation_size);
}

T_DECLARE_CASE(loadtable_rejects_string_block_overflow)
{
	/* The old unchecked sum wraps to one and reaches malloc(1). */
	const size_t lengths[] = { SIZE_MAX - 1, 1 };
	T_CALL_SUBCASE(
		expect_string_size_failure, lengths, ARRAY_SIZE(lengths), 0, 0,
		false);
	T_CALL_SUBCASE(
		expect_string_size_failure, lengths, ARRAY_SIZE(lengths), 0, 0,
		true);
}

T_DECLARE_CASE(loadtable_checks_string_block_limit)
{
	/* Exactly SIZE_MAX bytes are representable: allocation, not arithmetic,
	 * fails. One additional terminator must be rejected before allocating. */
	const size_t exact[] = { SIZE_MAX - 1 };
	T_CALL_SUBCASE(
		expect_string_size_failure, exact, ARRAY_SIZE(exact), 1,
		SIZE_MAX, false);
	T_CALL_SUBCASE(
		expect_string_size_failure, exact, ARRAY_SIZE(exact), 1,
		SIZE_MAX, true);
	const size_t overflow[] = { SIZE_MAX - 1, 0 };
	T_CALL_SUBCASE(
		expect_string_size_failure, overflow, ARRAY_SIZE(overflow), 0,
		0, false);
	T_CALL_SUBCASE(
		expect_string_size_failure, overflow, ARRAY_SIZE(overflow), 0,
		0, true);
}

T_DECLARE_CASE(loadtable_applies_typed_fields)
{
	lua_State *L = new_conf_table(_t_);
	T_CHECK(L != NULL);

	lua_pushstring(L, "0.0.0.0:1080");
	lua_setfield(L, -2, "listen");
	lua_pushinteger(L, 5);
	lua_setfield(L, -2, "loglevel");
	lua_pushnumber(L, 12.5);
	lua_setfield(L, -2, "timeout");
	lua_pushboolean(L, 0);
	lua_setfield(L, -2, "tcp_nodelay");
	lua_pushinteger(L, 4242);
	lua_setfield(L, -2, "max_sessions");

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(conf_loadfromtable(L, conf));
	T_EXPECT(
		conf->listen != NULL &&
		strcmp(conf->listen, "0.0.0.0:1080") == 0);
	T_EXPECT_EQ(conf->loglevel, 5);
	T_EXPECT(conf->timeout == 12.5);
	T_EXPECT(!conf->tcp_nodelay);
	T_EXPECT_EQ(conf->max_sessions, 4242);

	clear_config(conf);
	close_test_lua(L);
}

T_DECLARE_CASE(loadtable_empty_preserves_defaults)
{
	lua_State *L = new_conf_table(_t_);
	T_CHECK(L != NULL);

	const struct config def = conf_default();
	struct config *conf = new_config(_t_, conf_default());
	/* nil for every field must keep the existing values */
	T_EXPECT(conf_loadfromtable(L, conf));
	T_EXPECT_EQ(conf->loglevel, def.loglevel);
	T_EXPECT_EQ(conf->max_sessions, def.max_sessions);
	T_EXPECT(conf->timeout == def.timeout);

	clear_config(conf);
	close_test_lua(L);
}

T_DECLARE_CASE(loadtable_rejects_wrong_types)
{
	/* integer field with a non-integer value */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushstring(L, "notanint");
		lua_setfield(L, -2, "loglevel");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	/* integer field out of the int range. Gated to a 64-bit lua_Integer:
	 * on a LUA_32BITS build lua_Integer is int, so no representable value
	 * is out of int range (INT_MAX + 1 would overflow the constant), and
	 * conf_loadfromtable's INT_MIN/INT_MAX bound is correctly unreachable
	 * there -- there is nothing to reject. */
#if !LUA_32BITS
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, (lua_Integer)INT_MAX + 1);
		lua_setfield(L, -2, "max_sessions");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
#endif /* !LUA_32BITS */
	/* double field with a non-number value */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushboolean(L, 1);
		lua_setfield(L, -2, "timeout");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	/* double field with a numeric string: must be rejected too, matching
	 * the strict CONF_INT/CONF_BOOL checks (lua_isnumber would accept it) */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushstring(L, "30");
		lua_setfield(L, -2, "timeout");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	/* boolean field with a non-boolean value */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, 1);
		lua_setfield(L, -2, "tcp_nodelay");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	/* string field with a non-string value */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, 1);
		lua_setfield(L, -2, "listen");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
}

T_DECLARE_CASE(loadtable_rejects_invalid_config_values)
{
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, -1);
		lua_setfield(L, -2, "resolve_pf");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, -1);
		lua_setfield(L, -2, "max_sessions");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, 0);
		lua_setfield(L, -2, "max_sessions");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(conf_loadfromtable(L, conf));
		T_EXPECT_EQ(conf->max_sessions, 0);
		clear_config(conf);
		close_test_lua(L);
	}
}

/*
 * Regression: a bad string field must not leave an already-applied
 * non-string field behind. All fields are now validated before any of
 * them are mutated, so failure on the string field must leave loglevel
 * at its untouched default instead of the value from this same table.
 */
T_DECLARE_CASE(loadtable_rejects_all_or_nothing_across_field_kinds)
{
	lua_State *L = new_conf_table(_t_);
	T_CHECK(L != NULL);
	lua_pushinteger(L, 5);
	lua_setfield(L, -2, "loglevel");
	lua_pushinteger(L, 1); /* wrong type: listen must be a string */
	lua_setfield(L, -2, "listen");

	const struct config def = conf_default();
	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadfromtable(L, conf));
	T_EXPECT_EQ(conf->loglevel, def.loglevel);

	clear_config(conf);
	close_test_lua(L);
}

/*
 * Regression: a string field set by an earlier call and left nil by a
 * later one (e.g. an operator's boot config dropping a field between
 * SIGHUP reloads) must not dangle into the block the later call frees.
 */
T_DECLARE_CASE(loadtable_second_call_does_not_dangle_prior_string)
{
	lua_State *L1 = new_conf_table(_t_);
	T_CHECK(L1 != NULL);
	lua_pushstring(L1, "192.168.1.1:1080");
	lua_setfield(L1, -2, "listen");

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(conf_loadfromtable(L1, conf));
	T_EXPECT(conf->listen != NULL);
	T_EXPECT_STREQ(conf->listen, "192.168.1.1:1080");
	close_test_lua(L1);

	/* second call: listen is nil this time */
	lua_State *L2 = new_conf_table(_t_);
	T_CHECK(L2 != NULL);
	lua_pushinteger(L2, 5);
	lua_setfield(L2, -2, "loglevel");

	T_EXPECT(conf_loadfromtable(L2, conf));
	/* must still be readable: the string must have been carried into
	 * the new block, not left dangling into the block just freed */
	T_EXPECT(conf->listen != NULL);
	T_EXPECT_STREQ(conf->listen, "192.168.1.1:1080");

	clear_config(conf);
	close_test_lua(L2);
}

/*
 * daemonize and user_name are command-line-only settings.
 * conf_loadfromtable rejects either field in a configuration table.
 */
T_DECLARE_CASE(loadtable_rejects_cli_only_fields)
{
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushboolean(L, 1);
		lua_setfield(L, -2, "daemonize");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushstring(L, "nobody:nogroup");
		lua_setfield(L, -2, "user_name");
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
}

/*
 * Regression: conf_check enforces the domain of every numeric field, but it
 * ran only on the command line. A boot config applied at runtime -- the
 * SIGHUP reload path -- committed straight into the live config, so a table
 * could install values the daemon would have refused to start with: timeout
 * = 0 makes every connection timer fire on the next loop iteration.
 */
T_DECLARE_CASE(loadtable_rejects_out_of_range_fields)
{
	static const struct {
		const char *key;
		lua_Integer value;
	} badints[] = {
		{ "loglevel", LOG_LEVEL_VERYVERBOSE + 1 },
		{ "startup_limit_rate", 1000 },
#if WITH_TCP_KEEPALIVE_PARAMS
		{ "tcp_keepcnt", 128 },
#endif
#if WITH_THREADS
		{ "workers", 4096 },
#endif
	};
	for (size_t i = 0; i < ARRAY_SIZE(badints); i++) {
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushinteger(L, badints[i].value);
		lua_setfield(L, -2, badints[i].key);
		struct config *conf = new_config(_t_, make_valid_conf());
		T_EXPECT(!conf_loadfromtable(L, conf));
		clear_config(conf);
		close_test_lua(L);
	}
	/* the rejected table leaves every field of the live config alone */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushnumber(L, 0.0);
		lua_setfield(L, -2, "timeout");
		lua_pushinteger(L, LOG_LEVEL_VERBOSE);
		lua_setfield(L, -2, "loglevel");
		const struct config def = conf_default();
		struct config *conf = new_config(_t_, make_valid_conf());
		T_EXPECT(!conf_loadfromtable(L, conf));
		T_EXPECT(conf->timeout == def.timeout);
		T_EXPECT_EQ(conf->loglevel, def.loglevel);
		clear_config(conf);
		close_test_lua(L);
	}
	/* the boundary value itself still loads */
	{
		lua_State *L = new_conf_table(_t_);
		T_CHECK(L != NULL);
		lua_pushnumber(L, 5.0);
		lua_setfield(L, -2, "timeout");
		struct config *conf = new_config(_t_, make_valid_conf());
		T_EXPECT(conf_loadfromtable(L, conf));
		T_EXPECT(conf->timeout == 5.0);
		clear_config(conf);
		close_test_lua(L);
	}
}

/* conf_loadfromtable on the table at index 1, filling the config at index 2. */
static int loadfromtable_body(lua_State *restrict L)
{
	struct config *restrict const conf = lua_touserdata(L, 2);
	lua_settop(L, 1);
	lua_pushboolean(L, conf_loadfromtable(L, conf));
	return 1;
}

/*
 * conf_loadfromtable reports a bad field by return value, but it reads the
 * config table with unprotected lua_getfield calls: a raising __index leaves
 * through a Lua error instead. Every caller must therefore supply a protected
 * frame, which is what conf.h documents.
 */
T_DECLARE_CASE(loadtable_raises_instead_of_returning_false)
{
	lua_State *restrict L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	luaL_openlibs(L);
	/* raises on the very first read, the unprotected cli_only scan */
	static const char src[] = "return setmetatable({}, "
				  "{ __index = function() error('boom') end })";
	T_CHECK(load_printed_conf(L, src));

	struct config conf = make_valid_conf();
	lua_pushcfunction(L, loadfromtable_body);
	lua_insert(L, -2);
	lua_pushlightuserdata(L, &conf);
	/* not LUA_OK: the error escaped conf_loadfromtable rather than being
	 * turned into a false return */
	T_EXPECT(lua_pcall(L, 2, 1, 0) != LUA_OK);
	T_EXPECT(conf.strings == NULL);

	close_test_lua(L);
}

/* Load a config from the metatabled table returned by the Lua expression
 * `src`, returning conf_loadfromtable's verdict and filling *conf (whose
 * .strings the caller frees; it stays NULL on failure). */
static bool
load_metatable_conf(const char *restrict src, struct config *restrict conf)
{
	*conf = conf_default();
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return false;
	}
	luaL_openlibs(L);
	bool ok = false;
	if (luaL_dostring(L, src) == LUA_OK && lua_istable(L, -1)) {
		ok = conf_loadfromtable(L, conf);
	}
	lua_close(L);
	return ok;
}

T_DECLARE_CASE(loadtable_rejects_embedded_nul_strings)
{
	static const char *const fields[] = {
		"listen",     "forward", "proxy", "restapi", "http_listen",
#if WITH_CARES
		"nameserver",
#endif
#if WITH_NETDEVICE
		"netdev",
#endif
	};
	lua_State *L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	bool rejected = true;
	bool unchanged = true;
	for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
		struct config *conf = new_config(_t_, make_valid_conf());
		lua_newtable(L);
		static const char value[] = "prefix\0suffix";
		lua_pushlstring(L, value, sizeof(value) - 1);
		lua_setfield(L, -2, fields[i]);
		lua_pushinteger(L, 7);
		lua_setfield(L, -2, "loglevel");
		const bool ok = conf_loadfromtable(L, conf);
		const bool intact = conf->loglevel == LOG_LEVEL_NOTICE &&
				    strcmp(conf->listen, "127.0.0.1:1080") == 0;
		clear_config(conf);
		lua_pop(L, 1);
		rejected = rejected && !ok;
		unchanged = unchanged && intact;
	}
	close_test_lua(L);
	T_EXPECT(rejected);
	T_EXPECT(unchanged);
}

T_DECLARE_CASE(loadtable_uses_first_string_value)
{
	static const char *const measured[] = { "nil", "'good'" };
	for (size_t i = 0; i < ARRAY_SIZE(measured); i++) {
		char src[512];
		(void)snprintf(
			src, sizeof(src),
			"local n=0 return setmetatable({loglevel=7}, {__index=function(_,k) "
			"if k=='listen' then n=n+1 if n==1 then return %s end "
			"return 'bad'..string.char(0)..'suffix' end end})",
			measured[i]);
		struct config *conf = new_config(_t_, conf_default());
		const bool ok = load_metatable_conf(src, conf);
		const bool intact =
			conf->loglevel == 7 &&
			(i == 0 ? conf->listen == NULL :
				  conf->listen != NULL &&
					  strcmp(conf->listen, "good") == 0);
		clear_config(conf);
		T_EXPECT(ok);
		T_EXPECT(intact);
	}
}

T_DECLARE_CASE(loadtable_retains_first_metatable_values)
{
	{
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(load_metatable_conf(
			"local n = {}\n"
			"return setmetatable({}, { __index = function(_, k)\n"
			"  n[k] = (n[k] or 0) + 1\n"
			"  if k == 'listen' then\n"
			"    if n[k] == 1 then return 'ab' end\n"
			"    return 'abcdefghij'\n"
			"  end\n"
			"  return nil\n"
			"end })\n",
			conf));
		T_EXPECT(conf->listen != NULL);
		T_EXPECT_STREQ(conf->listen, "ab");
		clear_config(conf);
	}
	{
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(load_metatable_conf(
			"local n = {}\n"
			"return setmetatable({}, { __index = function(_, k)\n"
			"  n[k] = (n[k] or 0) + 1\n"
			"  if k == 'listen' then\n"
			"    if n[k] == 1 then return 'hello' end\n"
			"    return nil\n"
			"  end\n"
			"  return nil\n"
			"end })\n",
			conf));
		T_EXPECT_STREQ(conf->listen, "hello");
		clear_config(conf);
	}
	{
		struct config *conf = new_config(_t_, conf_default());
		T_EXPECT(load_metatable_conf(
			"local n = {}\n"
			"return setmetatable({}, { __index = function(_, k)\n"
			"  n[k] = (n[k] or 0) + 1\n"
			"  if k == 'listen' then return 'ab' end\n"
			"  if k == 'forward' then\n"
			"    if n[k] == 1 then return nil end\n"
			"    return 'zz'\n"
			"  end\n"
			"  return nil\n"
			"end })\n",
			conf));
		T_EXPECT_STREQ(conf->listen, "ab");
		T_EXPECT(conf->forward == NULL);
		clear_config(conf);
	}
}

T_DECLARE_CASE(loadtable_anchors_snapshot_strings)
{
	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(load_metatable_conf(
		"local t={} local seen={} return setmetatable(t, {__index=function(_,k) "
		"assert(not seen[k], k..' read twice') seen[k]=true "
		"if k=='listen' then return string.rep('a',4096) end "
		"if k=='forward' then rawset(t,'listen','changed') collectgarbage() "
		"return 'destination' end end})",
		conf));
	T_CHECK(conf->listen != NULL);
	T_EXPECT_EQ(strlen(conf->listen), (size_t)4096);
	T_EXPECT_EQ(strspn(conf->listen, "a"), (size_t)4096);
	T_EXPECT_STREQ(conf->forward, "destination");
	clear_config(conf);
}

#if WITH_RULESET
T_DECLARE_CASE(loadtable_validates_memlimit_range)
{
	static const int values[] = { INT_MIN, 0, INT_LEAST32_MAX >> 10,
				      (INT_LEAST32_MAX >> 10) + 1 };
	lua_State *L = new_test_lua(_t_);
	T_CHECK(L != NULL);
	for (size_t i = 0; i < ARRAY_SIZE(values); i++) {
		struct config *conf = new_config(_t_, make_valid_conf());
		lua_newtable(L);
		lua_pushinteger(L, values[i]);
		lua_setfield(L, -2, "memlimit");
		const int top = lua_gettop(L);
		const bool ok = conf_loadfromtable(L, conf);
		T_EXPECT_EQ(ok, i + 1 < ARRAY_SIZE(values));
		T_EXPECT_EQ(lua_gettop(L), top);
		T_EXPECT_EQ(conf->memlimit, ok ? values[i] : 0);
		clear_config(conf);
		lua_pop(L, 1);
	}
	close_test_lua(L);
}
#endif /* WITH_RULESET */

/* conf_reloadfromtable tests */

/* Reload the table returned by the Lua chunk `src` into *conf, the config the
 * running server was started with, returning conf_reloadfromtable's verdict.
 * A committed load leaves conf->strings for the caller to free. */
static bool reload_conf(
	const char *restrict src, struct config *restrict conf,
	const bool has_ruleset)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return false;
	}
	bool ok = false;
	if (luaL_dostring(L, src) == LUA_OK && lua_istable(L, -1)) {
		ok = conf_reloadfromtable(L, conf, has_ruleset);
	}
	lua_close(L);
	return ok;
}

T_DECLARE_CASE(reloadtable_rejects_embedded_nul_atomically)
{
	struct config *conf = new_config(_t_, make_valid_conf());
	T_EXPECT(reload_conf(
		"return { proxy = 'socks5://127.0.0.1:1081' }", conf, true));
	char *const strings = conf->strings;
	const bool ok = reload_conf(
		"return { proxy = 'socks5://127.0.0.1:1082\\0ignored', loglevel = 7 }",
		conf, true);
	const bool intact =
		conf->strings == strings &&
		strcmp(conf->proxy, "socks5://127.0.0.1:1081") == 0 &&
		conf->loglevel == LOG_LEVEL_NOTICE;
	clear_config(conf);
	T_EXPECT(!ok);
	T_EXPECT(intact);
}

#if WITH_RULESET
/*
 * main() refuses to start with auth_required and no ruleset installed, since
 * nothing would check the credentials. A reload must refuse the same config
 * rather than commit it into the running server, while the initial load still
 * defers the check to main(), which knows the ruleset only after `-r' loads.
 */
T_DECLARE_CASE(reloadtable_auth_required_requires_ruleset)
{
	struct config *conf = new_config(_t_, make_valid_conf());
	T_EXPECT(!reload_conf("return { auth_required = true }", conf, false));
	T_EXPECT(!conf->auth_required);
	T_EXPECT(conf->strings == NULL);

	T_EXPECT(reload_conf("return { auth_required = true }", conf, true));
	T_EXPECT(conf->auth_required);
	clear_config(conf);

	*conf = make_valid_conf();
	lua_State *L = new_conf_table(_t_);
	T_CHECK(L != NULL);
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "auth_required");
	T_EXPECT(conf_loadfromtable(L, conf));
	T_EXPECT(conf->auth_required);
	clear_config(conf);
	close_test_lua(L);
}
#endif /* WITH_RULESET */

/*
 * A reload must pass the rules conf_check enforces at startup: each of these
 * configs is refused on the command line, and must not become live through a
 * SIGHUP either. The config is left untouched, not partially committed.
 */
T_DECLARE_CASE(reloadtable_applies_startup_checks)
{
	static const char *const refused[] = {
		"return { proxy = 'socks5://127.0.0.1:1', socks5_udp = true }",
		"return { proxy = 'socks5://127.0.0.1:1', socks5_bind = true }",
		"return { block_global = true, block_local = true }",
		"return { timeout = 1.0 }",
	};
	for (size_t i = 0; i < ARRAY_SIZE(refused); i++) {
		struct config conf = make_valid_conf();
		T_EXPECT(!reload_conf(refused[i], &conf, true));
		T_EXPECT(conf.proxy == NULL);
		T_EXPECT(!conf.block_global);
		T_EXPECT(conf.strings == NULL);
	}

#if WITH_RULESET
	/* authentication is unsupported in forward mode, ruleset or not */
	struct config conf = make_valid_conf();
	conf.forward = "127.0.0.1:80";
	T_EXPECT(!reload_conf("return { auth_required = true }", &conf, true));
	T_EXPECT(!conf.auth_required);
	T_EXPECT(conf.strings == NULL);
#endif /* WITH_RULESET */
}

/*
 * The listeners, their socket options, the serve mode chosen by whether
 * `forward' is set, and the worker threads are set up once at startup; a
 * reload that changes one of them could not take effect, and committing it
 * would make neosocksd.config() report a configuration nothing runs. Restating
 * the running value, or changing the forward destination itself, is allowed.
 */
T_DECLARE_CASE(reloadtable_refuses_startup_only_fields)
{
	static const char *const refused[] = {
		"return { listen = '127.0.0.1:1081' }",
		"return { http_listen = '127.0.0.1:8080' }",
		"return { restapi = '127.0.0.1:9080' }",
		"return { forward = '127.0.0.1:80' }",
#if WITH_TPROXY
		"return { transparent = true }",
#endif
#if WITH_REUSEPORT
		"return { reuseport = true }",
#endif
#if WITH_TCP_FASTOPEN
		"return { tcp_fastopen = false }",
#endif
#if WITH_THREADS
		"return { workers = 3 }",
#endif
	};
	for (size_t i = 0; i < ARRAY_SIZE(refused); i++) {
		struct config *conf = new_config(_t_, make_valid_conf());
		conf->max_sessions = 7;
		char src[128];
		const int n = snprintf(
			src, sizeof(src),
			"local t = %s t.max_sessions = 9 return t",
			refused[i] + strlen("return "));
		T_CHECK(n > 0 && (size_t)n < sizeof(src));
		T_EXPECT(!reload_conf(src, conf, true));
		T_EXPECT_EQ(conf->max_sessions, 7);
		T_EXPECT_STREQ(conf->listen, "127.0.0.1:1080");
		T_EXPECT(conf->forward == NULL);
		T_EXPECT(conf->strings == NULL);
	}

	struct config *conf = new_config(_t_, make_valid_conf());
	conf->forward = "127.0.0.1:80";
	T_EXPECT(reload_conf(
		"return { listen = '127.0.0.1:1080', forward = '127.0.0.1:81' }",
		conf, true));
	T_EXPECT_STREQ(conf->listen, "127.0.0.1:1080");
	T_EXPECT_STREQ(conf->forward, "127.0.0.1:81");
	clear_config(conf);
}

/* conf_loadboot tests */

static const char *write_tempfile_bin(
	struct testing_ctx *_t_, const void *restrict data, const size_t len)
{
	static const char tmpl[] = TEST_TMPDIR "/conf_test_XXXXXX";
	struct conf_fixture *f = new_fixture(_t_);
	f->path = malloc(sizeof(tmpl));
	T_CHECK(f->path != NULL);
	memcpy(f->path, tmpl, sizeof(tmpl));
	const int fd = mkstemp(f->path);
	if (fd < 0) {
		free(f->path);
		f->path = NULL;
		return NULL;
	}
	const ssize_t n = write(fd, data, len);
	const int err = close(fd);
	return n >= 0 && (size_t)n == len && err == 0 ? f->path : NULL;
}

static const char *
write_tempfile(struct testing_ctx *_t_, const char *restrict content)
{
	return write_tempfile_bin(_t_, content, strlen(content));
}

static struct conf_fixture *new_gzip_fixture(struct testing_ctx *_t_)
{
	struct conf_fixture *f = new_fixture(_t_);
	f->buffer = VBUF_NEW(64);
	T_CHECK(f->buffer != NULL);
	f->writer = codec_gzip_writer(io_heapwriter(&f->buffer));
	T_CHECK(f->writer != NULL);
	return f;
}

T_DECLARE_CASE(loadboot_library_oom_closes_resources)
{
	const char *path =
		write_tempfile(_t_, "return {listen='127.0.0.1:1080'}");
	T_CHECK(path != NULL);
	struct config conf = conf_default();
	boot_vm_closed = 0;
	boot_stream_closed = 0;
	boot_alloc_failures = 0;
	boot_oom = true;
	const bool ok = conf_loadboot(&conf, path);
	boot_oom = false;
	free(conf.strings);
	T_EXPECT(!ok);
	T_EXPECT(boot_alloc_failures > 0);
	T_EXPECT_EQ(boot_vm_closed, (size_t)1);
	T_EXPECT_EQ(boot_stream_closed, (size_t)1);
	T_EXPECT_EQ(conf.listen, NULL);
}

/*
 * Regression: a read error part-way through the config stream must fail the
 * load, not silently compile whatever arrived first. lua_Reader has no error
 * channel, so a reader that just logs and returns its buffer leaves lua_load()
 * treating the truncation as a clean EOF.
 *
 * A gzip member with its 8-byte CRC/ISIZE trailer cut off drives exactly that:
 * codec_lua_reader auto-detects gzip, the deflate data is intact so the full
 * (valid, table-returning) source still reaches lua_load, and only then does
 * the codec report the missing trailer. Before the fix conf_loadboot accepted
 * this corrupt config.
 */
T_DECLARE_CASE(loadboot_rejects_truncated_stream)
{
	static const char src[] = "return { listen = \"0.0.0.0:1080\" }\n";
	struct conf_fixture *f = new_gzip_fixture(_t_);
	size_t n = sizeof(src) - 1;
	T_EXPECT_EQ(io_stream_write(f->writer, src, &n), 0);
	T_EXPECT_EQ(n, sizeof(src) - 1);
	const int err = io_stream_close(f->writer);
	f->writer = NULL;
	T_EXPECT_EQ(err, 0);
	T_CHECK(f->buffer != NULL);
	/* the gzip trailer is the last 8 bytes (CRC-32 + ISIZE) */
	T_CHECK(VBUF_LEN(f->buffer) > 8);

	const char *path = write_tempfile_bin(
		_t_, VBUF_DATA(f->buffer), VBUF_LEN(f->buffer) - 8);
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

T_DECLARE_CASE(loadboot_rejects_embedded_nul)
{
	const char *path = write_tempfile(
		_t_, "return {listen='127.0.0.1:1080\\0ignored',loglevel=7}");
	T_CHECK(path != NULL);
	struct config *conf = new_config(_t_, conf_default());
	const bool ok = conf_loadboot(conf, path);
	const bool intact =
		conf->listen == NULL && conf->loglevel == LOG_LEVEL_NOTICE;
	clear_config(conf);
	T_EXPECT(!ok);
	T_EXPECT(intact);
}

T_DECLARE_CASE(loadboot_applies_config_table)
{
	const char *path = write_tempfile(
		_t_, "return { listen = \"0.0.0.0:1080\", loglevel = 5 }");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(conf_loadboot(conf, path));
	T_EXPECT_STREQ(conf->listen, "0.0.0.0:1080");
	T_EXPECT_EQ(conf->loglevel, 5);

	clear_config(conf);
}

/*
 * A `ruleset` field can only be honored by the ruleset-aware loader in
 * ruleset.c, which is unavailable in this build; conf_loadboot must reject
 * it rather than silently drop it.
 */
T_DECLARE_CASE(loadboot_rejects_ruleset_field)
{
	const char *path = write_tempfile(
		_t_, "return { listen = \"0.0.0.0:1080\", ruleset = {} }");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

/*
 * auth_required can only ever be enforced by process_cb, which requires a
 * ruleset; a boot config setting it must take effect when enforcement is
 * possible (WITH_RULESET), and be silently ignored otherwise, rather than
 * leaving an unenforceable auth_required=true in effect.
 */
T_DECLARE_CASE(loadboot_auth_required_requires_ruleset)
{
	const char *path = write_tempfile(
		_t_,
		"return { listen = \"0.0.0.0:1080\", auth_required = true }");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(conf_loadboot(conf, path));
#if WITH_RULESET
	T_EXPECT(conf->auth_required);
#else /* WITH_RULESET */
	T_EXPECT(!conf->auth_required);
#endif /* WITH_RULESET */

	clear_config(conf);
}

T_DECLARE_CASE(loadboot_rejects_non_table_return)
{
	const char *path = write_tempfile(_t_, "return 42");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

T_DECLARE_CASE(loadboot_rejects_syntax_error)
{
	const char *path = write_tempfile(_t_, "not valid lua $$$");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

T_DECLARE_CASE(loadboot_rejects_missing_file)
{
	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(
		conf, TEST_TMPDIR "/conf_test_does_not_exist_XXXXXX"));
	clear_config(conf);
}

/*
 * Regression: field extraction from the returned config table runs on a state
 * with no panic handler, so a __index metamethod that raises must be caught and
 * turned into a load failure -- before the fix it hit Lua's default panic and
 * abort()ed the process.
 */
T_DECLARE_CASE(loadboot_rejects_raising_metatable)
{
	const char *path = write_tempfile(
		_t_,
		"return setmetatable({}, { __index = function() error('boom') end })");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

/*
 * Regression: a config chunk that raises a non-string error object must fail
 * cleanly. lua_tostring on a non-string yields NULL, and formatting NULL with
 * "%s" is undefined behavior -- the load must still just return false.
 */
T_DECLARE_CASE(loadboot_rejects_non_string_error)
{
	const char *path = write_tempfile(_t_, "error(setmetatable({}, {}))");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(!conf_loadboot(conf, path));

	clear_config(conf);
}

T_DECLARE_CASE(loadboot_reads_metatable_field_once)
{
	const char *path = write_tempfile(
		_t_, "local n = {}\n"
		     "return setmetatable({}, { __index = function(_, k)\n"
		     "  if k == 'listen' then\n"
		     "    n[k] = (n[k] or 0) + 1\n"
		     "    if n[k] == 1 then return 'x' end\n"
		     "    error('boom')\n"
		     "  end\n"
		     "  return nil\n"
		     "end })\n");
	T_CHECK(path != NULL);

	struct config *conf = new_config(_t_, conf_default());
	T_EXPECT(conf_loadboot(conf, path));
	T_EXPECT_STREQ(conf->listen, "x");

	clear_config(conf);
}
#endif /* WITH_LUA */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(conf_capture_intentional_failure)
{
	const struct config conf = make_valid_conf();
	T_CHECK(capture_conf_advise(_t_, &conf, false) != NULL);
	T_CHECK(capture_help_text(_t_) != NULL);
	T_EXPECT(false);
}

T_DECLARE_CASE(conf_failed_expectation_cleans_captures)
{
	const unsigned released = released_captures;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, conf_capture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(released_captures, released + 2);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_fixtures, 0u);
	T_RUN_CASE(nested, parseargs_help_gate_matches_config_flag_parsing);
	T_RUN_CASE(nested, conf_advise_silent_without_ruleset_or_proxy);
	T_EXPECT_EQ(nested.passed, 2);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_fixtures, 0u);
}

#if WITH_LUA
static char failed_fixture_path[sizeof(TEST_TMPDIR "/conf_test_XXXXXX")];

T_DECLARE_CASE(conf_native_fixture_intentional_failure)
{
	const char *path = write_tempfile(_t_, "return {}");
	T_CHECK(path != NULL);
	memcpy(failed_fixture_path, path, sizeof(failed_fixture_path));
	struct conf_fixture *f = new_gzip_fixture(_t_);
	static const char src[] = "return {}";
	size_t len = sizeof(src) - 1;
	T_EXPECT_EQ(io_stream_write(f->writer, src, &len), 0);
	T_EXPECT_EQ(len, sizeof(src) - 1);
	T_EXPECT(false);
}

T_DECLARE_CASE(conf_failed_expectation_cleans_native_resources)
{
	const unsigned closed = released_writers;
	const unsigned freed = released_buffers;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, conf_native_fixture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(released_writers, closed + 1);
	T_EXPECT_EQ(released_buffers, freed + 1);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_fixtures, 0u);
	errno = 0;
	T_EXPECT_EQ(access(failed_fixture_path, F_OK), -1);
	T_EXPECT_EQ(errno, ENOENT);
	T_RUN_CASE(nested, loadboot_rejects_truncated_stream);
	T_EXPECT_EQ(nested.passed, 1);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_fixtures, 0u);
}

T_DECLARE_CASE(conf_fixture_intentional_failure)
{
	lua_State *L = new_conf_table(_t_);
	struct config *conf = new_config(_t_, conf_default());
	lua_pushliteral(L, "127.0.0.1:1080");
	lua_setfield(L, -2, "listen");
	T_CHECK(conf_loadfromtable(L, conf));
	T_CHECK(conf->strings != NULL);
	T_EXPECT(false);
}

T_DECLARE_CASE(conf_failed_expectation_cleans_fixture)
{
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, conf_fixture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_lua, 0u);
	T_EXPECT_EQ(live_fixtures, 0u);
	T_RUN_CASE(nested, loadtable_applies_typed_fields);
	T_EXPECT_EQ(nested.passed, 1);
	T_EXPECT(fixtures == NULL);
	T_EXPECT_EQ(live_lua, 0u);
	T_EXPECT_EQ(live_fixtures, 0u);
}
#endif /* WITH_LUA */

static const struct testing_suite suite[] = {
	T_CASE(conf_failed_expectation_cleans_captures),
#if WITH_LUA
	T_CASE(conf_failed_expectation_cleans_native_resources),
	T_CASE(conf_failed_expectation_cleans_fixture),
#endif
	T_CASE(conf_default_has_expected_values),
	T_CASE(conf_requires_listen),
	T_CASE(conf_rejects_incompatible_modes),
	T_CASE(conf_rejects_timeout_out_of_range),
	T_CASE(conf_rejects_loglevel_out_of_range),
	T_CASE(conf_rejects_startup_limits_out_of_range),
	T_CASE(conf_accepts_unlimited_startup_full),
#if WITH_THREADS
	T_CASE(conf_rejects_workers_out_of_range),
#endif
	T_CASE(parseargs_accepts_unlimited_max_startups),
	T_CASE(parseargs_rejects_empty_numeric_args),
	T_CASE(parseargs_rejects_wrapped_negative_integers),
	T_CASE(conf_rejects_proxy_with_socks5_extensions),
	T_CASE(conf_accepts_valid_configuration),
	T_CASE(conf_rejects_invalid_resolve_pf),
	T_CASE(conf_rejects_negative_max_sessions),
#if WITH_LUA
	T_CASE(conf_print_round_trips_control_char_before_digit),
#if !LUA_32BITS
	T_CASE(conf_print_round_trips_double_precision),
#endif
	T_CASE(conf_print_flushes_the_dump),
	T_CASE(conf_print_round_trips_every_field),
	T_CASE(conf_pushfield_matches_snapshot),
	T_CASE(conf_loadfromtable_reads_scalar_once),
	T_CASE(conf_loadfromtable_raise_leaves_config_unchanged),
#endif /* WITH_LUA */
	T_CASE(conf_warns_small_tcp_buffers),
	T_CASE(conf_rejects_block_global_and_local),
#if WITH_TCP_KEEPALIVE_PARAMS
	T_CASE(conf_default_keeps_system_keepalive_timing),
	T_CASE(conf_rejects_keepalive_timing_out_of_range),
	T_CASE(conf_warns_keepalive_timing_without_keepalive),
#endif
#if WITH_TPROXY
	T_CASE(conf_rejects_http_with_tproxy),
	T_CASE(conf_rejects_forward_with_tproxy),
#endif
	T_CASE(conf_advise_notes_ruleset_extends_proxy),
	T_CASE(conf_advise_silent_without_ruleset_or_proxy),
	T_CASE(conf_advise_notes_forward_placeholder_without_ruleset),
#if WITH_RULESET
	T_CASE(conf_rejects_ruleset_with_socks5_bind),
	T_CASE(conf_rejects_ruleset_with_socks5_udp),
#endif
	T_CASE(conf_rejects_auth_required_in_forward_mode),
#if WITH_RULESET
	T_CASE(conf_defers_auth_required_ruleset_check),
#endif
	T_CASE(parseargs_help_returns_false),
	T_CASE(parseargs_help_gate_matches_config_flag_parsing),
	T_CASE(parseargs_resolve_pf_flags),
	T_CASE(parseargs_http_with_address),
	T_CASE(parseargs_http_only),
	T_CASE(parseargs_http_followed_by_option),
	T_CASE(parseargs_http_only_requires_listen),
	T_CASE(parseargs_fastopen_connect),
	T_CASE(parseargs_proxy_and_api),
	T_CASE(parseargs_auth_required),
	T_CASE(parseargs_user_daemonize_color),
	T_CASE(parseargs_timeout),
	T_CASE(parseargs_loglevel),
	T_CASE(parseargs_log_outputs),
	T_CASE(parseargs_block_outbound),
	T_CASE(parseargs_max_sessions),
	T_CASE(parseargs_max_startups),
	T_CASE(parseargs_rejects_above_int_max_numeric),
	T_CASE(parseargs_rejects_numeric_trailing_junk),
	T_CASE(parseargs_double_dash_and_unknown),
#if WITH_CARES
	T_CASE(parseargs_nameserver),
#endif
#if WITH_TPROXY
	T_CASE(parseargs_tproxy),
#endif
#if WITH_NETDEVICE
	T_CASE(parseargs_netdev),
#endif
#if WITH_REUSEPORT
	T_CASE(parseargs_reuseport),
#endif
	T_CASE(parseargs_workers),
#if WITH_SPLICE
	T_CASE(parseargs_pipe),
#endif
#if WITH_TCP_FASTOPEN
	T_CASE(parseargs_no_fastopen),
#endif
#if WITH_RULESET
	T_CASE(parseargs_ruleset),
#endif
	T_CASE(parseargs_forward_flag),
	T_CASE(parseargs_block_multicast_token),
#if WITH_RULESET
	T_CASE(parseargs_config_and_ruleset_mutually_exclusive),
	T_CASE(parseargs_memlimit_negative_clamped),
#endif
#if WITH_LUA
	T_CASE(parseargs_config_flag),
	T_CASE(parseargs_dump_config),
	T_CASE(loadtable_rejects_string_block_overflow),
	T_CASE(loadtable_checks_string_block_limit),
	T_CASE(loadtable_applies_typed_fields),
	T_CASE(loadtable_empty_preserves_defaults),
	T_CASE(loadtable_rejects_wrong_types),
	T_CASE(loadtable_rejects_invalid_config_values),
	T_CASE(loadtable_rejects_all_or_nothing_across_field_kinds),
	T_CASE(loadtable_second_call_does_not_dangle_prior_string),
	T_CASE(loadtable_rejects_cli_only_fields),
	T_CASE(loadtable_retains_first_metatable_values),
	T_CASE(loadtable_anchors_snapshot_strings),
#if WITH_RULESET
	T_CASE(loadtable_validates_memlimit_range),
#endif
	T_CASE(loadtable_rejects_embedded_nul_strings),
	T_CASE(loadtable_uses_first_string_value),
	T_CASE(reloadtable_rejects_embedded_nul_atomically),
	T_CASE(loadboot_rejects_embedded_nul),
	T_CASE(loadtable_rejects_out_of_range_fields),
	T_CASE(loadtable_raises_instead_of_returning_false),
#if WITH_RULESET
	T_CASE(reloadtable_auth_required_requires_ruleset),
#endif
	T_CASE(reloadtable_applies_startup_checks),
	T_CASE(reloadtable_refuses_startup_only_fields),
	T_CASE(loadboot_applies_config_table),
	T_CASE(loadboot_rejects_ruleset_field),
	T_CASE(loadboot_auth_required_requires_ruleset),
	T_CASE(loadboot_rejects_non_table_return),
	T_CASE(loadboot_rejects_syntax_error),
	T_CASE(loadboot_library_oom_closes_resources),
	T_CASE(loadboot_rejects_truncated_stream),
	T_CASE(loadboot_rejects_raising_metatable),
	T_CASE(loadboot_rejects_non_string_error),
	T_CASE(loadboot_reads_metatable_field_once),
	T_CASE(loadboot_rejects_missing_file),
#endif /* WITH_LUA */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
