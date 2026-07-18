/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for conf.c; no stateful collaborators to mock. */

#include "conf.h"

#if WITH_LUA
#include "proto/codec.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"

#include <lauxlib.h>
#include <lua.h>
#endif /* WITH_LUA */

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - shared test fixtures (conf.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static struct config make_valid_conf(void)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	return conf;
}

/* Redirect fd_no (STDOUT_FILENO or STDERR_FILENO) to a tmpfile, run
 * action(data), restore fd_no, and return the captured bytes in a heap buffer
 * the caller must free. Returns NULL on any setup/I/O failure or when action
 * returns false. */
static char *
capture_fd(const int fd_no, bool (*action)(const void *), const void *data)
{
	FILE *const stream = (fd_no == STDOUT_FILENO) ? stdout : stderr;
	(void)fflush(stream);
	const int saved_fd = dup(fd_no);
	if (saved_fd < 0) {
		return NULL;
	}
	FILE *const tmp = tmpfile();
	if (tmp == NULL) {
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
	rewind(tmp);
	char *const buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		(void)fclose(tmp);
		return NULL;
	}
	const size_t n = fread(buf, 1, (size_t)size, tmp);
	(void)fclose(tmp);
	buf[n] = '\0';
	return buf;
}

#if WITH_LUA
static bool run_conf_print(const void *data)
{
	return conf_print(data);
}

/* Capture everything conf_print() writes to stdout into a heap buffer the
 * caller must free; returns NULL on any failure. */
static char *capture_conf_print(const struct config *restrict conf)
{
	return capture_fd(STDOUT_FILENO, run_conf_print, conf);
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
	static const char *const cases[][3] = {
		{ "--loglevel", "" },
		{ "-m", "" },
		{ "-t", "" },
		{ "--max-startups", ":5:10" },
		{ "--max-startups", "5::10" },
	};
	for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
		struct config conf = conf_default();
		char *argv[] = { "conf_test", (char *)cases[k][0],
				 (char *)cases[k][1] };
		T_EXPECT(!conf_parseargs(&conf, 3, argv));
	}
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

	char *const out = capture_conf_print(&conf);
	T_CHECK(out != NULL);

	lua_State *restrict L = luaL_newstate();
	T_CHECK(L != NULL);
	T_CHECK(load_printed_conf(L, out));
	free(out);

	lua_getfield(L, -1, "listen");
	T_CHECK(lua_isstring(L, -1));
	size_t len;
	const char *const listen = lua_tolstring(L, -1, &len);
	T_EXPECT_EQ(len, strlen(conf.listen));
	T_EXPECT_MEMEQ(listen, conf.listen, len);

	lua_close(L);
}

/*
 * Regression: %g's default 6 significant digits truncates timeout on a
 * --dump-config round trip; %.17g always recovers the exact double.
 */
T_DECLARE_CASE(conf_print_round_trips_double_precision)
{
	struct config conf = make_valid_conf();
	conf.timeout = 1.0 / 3.0;

	char *const out = capture_conf_print(&conf);
	T_CHECK(out != NULL);

	lua_State *restrict L = luaL_newstate();
	T_CHECK(L != NULL);
	T_CHECK(load_printed_conf(L, out));
	free(out);

	lua_getfield(L, -1, "timeout");
	T_CHECK(lua_isnumber(L, -1));
	T_EXPECT(lua_tonumber(L, -1) == conf.timeout);

	lua_close(L);
}
#endif /* WITH_LUA */

T_DECLARE_CASE(conf_warns_small_tcp_buffers)
{
	struct config conf = make_valid_conf();

	conf.tcp_sndbuf = 1024;
	conf.tcp_rcvbuf = 4096;
	T_EXPECT(conf_check(&conf)); /* warns but remains valid */
}

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

#if WITH_RULESET
T_DECLARE_CASE(conf_warns_ruleset_overrides_proxy)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.proxy = "socks5://127.0.0.1:1080";
	T_EXPECT(conf_check(&conf)); /* just a warning, still valid */
}

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

/* Capture what --help writes to stderr into a heap buffer the caller must
 * free; returns NULL on any failure. */
static char *capture_help_text(void)
{
	return capture_fd(STDERR_FILENO, run_help, NULL);
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
	char *const help = capture_help_text();
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

	free(help);
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
	/* restore a sane logging sink for the remainder of the test run */
	{
		struct config conf = conf_default();
		char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--log",
				 "terminal" };
		T_EXPECT(conf_parseargs(&conf, 5, argv));
	}
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

static lua_State *new_conf_table(void)
{
	lua_State *L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	lua_newtable(L);
	return L;
}

T_DECLARE_CASE(loadtable_applies_typed_fields)
{
	lua_State *L = new_conf_table();
	T_CHECK(L != NULL);

	lua_pushstring(L, "0.0.0.0:1080");
	lua_setfield(L, -2, "listen");
	lua_pushinteger(L, 5);
	lua_setfield(L, -2, "loglevel");
	lua_pushnumber(L, 12.5);
	lua_setfield(L, -2, "timeout");
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "daemonize");
	lua_pushinteger(L, 4242);
	lua_setfield(L, -2, "max_sessions");

	struct config conf = conf_default();
	T_EXPECT(conf_loadfromtable(L, &conf));
	T_EXPECT(
		conf.listen != NULL &&
		strcmp(conf.listen, "0.0.0.0:1080") == 0);
	T_EXPECT_EQ(conf.loglevel, 5);
	T_EXPECT(conf.timeout == 12.5);
	T_EXPECT(conf.daemonize);
	T_EXPECT_EQ(conf.max_sessions, 4242);

	free(conf.strings);
	lua_close(L);
}

T_DECLARE_CASE(loadtable_empty_preserves_defaults)
{
	lua_State *L = new_conf_table();
	T_CHECK(L != NULL);

	const struct config def = conf_default();
	struct config conf = conf_default();
	/* nil for every field must keep the existing values */
	T_EXPECT(conf_loadfromtable(L, &conf));
	T_EXPECT_EQ(conf.loglevel, def.loglevel);
	T_EXPECT_EQ(conf.max_sessions, def.max_sessions);
	T_EXPECT(conf.timeout == def.timeout);

	free(conf.strings);
	lua_close(L);
}

T_DECLARE_CASE(loadtable_rejects_wrong_types)
{
	/* integer field with a non-integer value */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushstring(L, "notanint");
		lua_setfield(L, -2, "loglevel");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
	}
	/* integer field out of the int range */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushinteger(L, (lua_Integer)INT_MAX + 1);
		lua_setfield(L, -2, "max_sessions");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
	}
	/* double field with a non-number value */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushboolean(L, 1);
		lua_setfield(L, -2, "timeout");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
	}
	/* double field with a numeric string: must be rejected too, matching
	 * the strict CONF_INT/CONF_BOOL checks (lua_isnumber would accept it) */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushstring(L, "30");
		lua_setfield(L, -2, "timeout");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
	}
	/* boolean field with a non-boolean value */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushinteger(L, 1);
		lua_setfield(L, -2, "daemonize");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
	}
	/* string field with a non-string value */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushinteger(L, 1);
		lua_setfield(L, -2, "listen");
		struct config conf = conf_default();
		T_EXPECT(!conf_loadfromtable(L, &conf));
		free(conf.strings);
		lua_close(L);
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
	lua_State *L = new_conf_table();
	T_CHECK(L != NULL);
	lua_pushinteger(L, 5);
	lua_setfield(L, -2, "loglevel");
	lua_pushinteger(L, 1); /* wrong type: listen must be a string */
	lua_setfield(L, -2, "listen");

	const struct config def = conf_default();
	struct config conf = conf_default();
	T_EXPECT(!conf_loadfromtable(L, &conf));
	T_EXPECT_EQ(conf.loglevel, def.loglevel);

	free(conf.strings);
	lua_close(L);
}

/*
 * Regression: a string field set by an earlier call and left nil by a
 * later one (e.g. an operator's boot config dropping a field between
 * SIGHUP reloads) must not dangle into the block the later call frees.
 */
T_DECLARE_CASE(loadtable_second_call_does_not_dangle_prior_string)
{
	lua_State *L1 = new_conf_table();
	T_CHECK(L1 != NULL);
	lua_pushstring(L1, "192.168.1.1:1080");
	lua_setfield(L1, -2, "listen");

	struct config conf = conf_default();
	T_EXPECT(conf_loadfromtable(L1, &conf));
	T_EXPECT(conf.listen != NULL);
	T_EXPECT_STREQ(conf.listen, "192.168.1.1:1080");
	lua_close(L1);

	/* second call: listen is nil this time */
	lua_State *L2 = new_conf_table();
	T_CHECK(L2 != NULL);
	lua_pushinteger(L2, 5);
	lua_setfield(L2, -2, "loglevel");

	T_EXPECT(conf_loadfromtable(L2, &conf));
	/* must still be readable: the string must have been carried into
	 * the new block, not left dangling into the block just freed */
	T_EXPECT(conf.listen != NULL);
	T_EXPECT_STREQ(conf.listen, "192.168.1.1:1080");

	free(conf.strings);
	lua_close(L2);
}

/* conf_loadboot tests */

static int write_tempfile(char *restrict tmpl, const char *restrict content)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	const size_t len = strlen(content);
	if ((size_t)write(fd, content, len) != len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	return close(fd);
}

static int write_tempfile_bin(
	char *restrict tmpl, const void *restrict data, const size_t len)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	const ssize_t n = write(fd, data, len);
	if (n < 0 || (size_t)n != len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	return close(fd);
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
	struct vbuffer *gz = VBUF_NEW(64);
	T_CHECK(gz != NULL);
	{
		struct stream *restrict w =
			codec_gzip_writer(io_heapwriter(&gz));
		T_CHECK(w != NULL);
		size_t n = sizeof(src) - 1;
		T_EXPECT_EQ(stream_write(w, src, &n), 0);
		T_EXPECT_EQ(n, sizeof(src) - 1);
		T_EXPECT_EQ(stream_close(w), 0);
	}
	T_CHECK(gz != NULL);
	/* the gzip trailer is the last 8 bytes (CRC-32 + ISIZE) */
	T_CHECK(VBUF_LEN(gz) > 8);

	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile_bin(path, VBUF_DATA(gz), VBUF_LEN(gz) - 8) == 0);
	VBUF_FREE(gz);

	struct config conf = conf_default();
	T_EXPECT(!conf_loadboot(&conf, path));

	free(conf.strings);
	(void)unlink(path);
}

T_DECLARE_CASE(loadboot_applies_config_table)
{
	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path,
			"return { listen = \"0.0.0.0:1080\", loglevel = 5 }") ==
		0);

	struct config conf = conf_default();
	T_EXPECT(conf_loadboot(&conf, path));
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:1080");
	T_EXPECT_EQ(conf.loglevel, 5);

	free(conf.strings);
	(void)unlink(path);
}

/*
 * A `ruleset` field can only be honored by the ruleset-aware loader in
 * ruleset.c, which is unavailable in this build; conf_loadboot must reject
 * it rather than silently drop it.
 */
T_DECLARE_CASE(loadboot_rejects_ruleset_field)
{
	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path,
			"return { listen = \"0.0.0.0:1080\", ruleset = {} }") ==
		0);

	struct config conf = conf_default();
	T_EXPECT(!conf_loadboot(&conf, path));

	free(conf.strings);
	(void)unlink(path);
}

/*
 * auth_required can only ever be enforced by process_cb, which requires a
 * ruleset; a boot config setting it must take effect when enforcement is
 * possible (WITH_RULESET), and be silently ignored otherwise, rather than
 * leaving an unenforceable auth_required=true in effect.
 */
T_DECLARE_CASE(loadboot_auth_required_requires_ruleset)
{
	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path,
			"return { listen = \"0.0.0.0:1080\", auth_required = true }") ==
		0);

	struct config conf = conf_default();
	T_EXPECT(conf_loadboot(&conf, path));
#if WITH_RULESET
	T_EXPECT(conf.auth_required);
#else /* WITH_RULESET */
	T_EXPECT(!conf.auth_required);
#endif /* WITH_RULESET */

	free(conf.strings);
	(void)unlink(path);
}

T_DECLARE_CASE(loadboot_rejects_non_table_return)
{
	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return 42") == 0);

	struct config conf = conf_default();
	T_EXPECT(!conf_loadboot(&conf, path));

	free(conf.strings);
	(void)unlink(path);
}

T_DECLARE_CASE(loadboot_rejects_syntax_error)
{
	char path[] = "/tmp/conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "not valid lua $$$") == 0);

	struct config conf = conf_default();
	T_EXPECT(!conf_loadboot(&conf, path));

	free(conf.strings);
	(void)unlink(path);
}

T_DECLARE_CASE(loadboot_rejects_missing_file)
{
	struct config conf = conf_default();
	T_EXPECT(!conf_loadboot(&conf, "/tmp/conf_test_does_not_exist_XXXXXX"));
	free(conf.strings);
}
#endif /* WITH_LUA */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(conf_default_has_expected_values),
	T_CASE(conf_requires_listen),
	T_CASE(conf_rejects_incompatible_modes),
	T_CASE(conf_rejects_timeout_out_of_range),
	T_CASE(conf_rejects_loglevel_out_of_range),
	T_CASE(conf_rejects_startup_limits_out_of_range),
	T_CASE(conf_accepts_unlimited_startup_full),
	T_CASE(parseargs_accepts_unlimited_max_startups),
	T_CASE(parseargs_rejects_empty_numeric_args),
	T_CASE(conf_rejects_proxy_with_socks5_extensions),
	T_CASE(conf_accepts_valid_configuration),
#if WITH_LUA
	T_CASE(conf_print_round_trips_control_char_before_digit),
	T_CASE(conf_print_round_trips_double_precision),
#endif
	T_CASE(conf_warns_small_tcp_buffers),
	T_CASE(conf_rejects_block_global_and_local),
#if WITH_TPROXY
	T_CASE(conf_rejects_http_with_tproxy),
	T_CASE(conf_rejects_forward_with_tproxy),
#endif
#if WITH_RULESET
	T_CASE(conf_warns_ruleset_overrides_proxy),
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
	T_CASE(parseargs_proxy_and_api),
	T_CASE(parseargs_auth_required),
	T_CASE(parseargs_user_daemonize_color),
	T_CASE(parseargs_timeout),
	T_CASE(parseargs_loglevel),
	T_CASE(parseargs_log_outputs),
	T_CASE(parseargs_block_outbound),
	T_CASE(parseargs_max_sessions),
	T_CASE(parseargs_max_startups),
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
	T_CASE(loadtable_applies_typed_fields),
	T_CASE(loadtable_empty_preserves_defaults),
	T_CASE(loadtable_rejects_wrong_types),
	T_CASE(loadtable_rejects_all_or_nothing_across_field_kinds),
	T_CASE(loadtable_second_call_does_not_dangle_prior_string),
	T_CASE(loadboot_applies_config_table),
	T_CASE(loadboot_rejects_ruleset_field),
	T_CASE(loadboot_auth_required_requires_ruleset),
	T_CASE(loadboot_rejects_non_table_return),
	T_CASE(loadboot_rejects_syntax_error),
	T_CASE(loadboot_rejects_truncated_stream),
	T_CASE(loadboot_rejects_missing_file),
#endif /* WITH_LUA */
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
