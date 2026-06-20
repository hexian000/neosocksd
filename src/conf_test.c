/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * conf_test - white-box unit tests for conf.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   conf.c           module under test
 *   proto/codec.c    leaf (transfer codecs)
 *   version.c        leaf (neosocksd_version)
 * conf.c parses argv/config into struct config and has no stateful
 * collaborator module to mock; the mock section only holds shared fixtures.
 */

#include "conf.h"

#include "utils/slog.h"
#include "utils/testing.h"

#if WITH_LUA
#include "lauxlib.h"
#include "lua.h"
#endif

#include <sys/socket.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared test fixtures (conf.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static struct config make_valid_conf(void)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	return conf;
}

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

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.auth_required);
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
	for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) {
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

#if WITH_RULESET
T_DECLARE_CASE(parseargs_dump_config_deprecated)
{
	/* --dump-config is accepted but deprecated (no-op) */
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--dump-config" };
	T_EXPECT(conf_parseargs(&conf, 4, argv));
}
#endif /* WITH_RULESET */

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

#if WITH_RULESET
T_DECLARE_CASE(parseargs_config_flag)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-c",
			 "boot.lua" };
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT(conf.boot != NULL && strcmp(conf.boot, "boot.lua") == 0);
}

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
	lua_setfield(L, -2, "auth_required");
	lua_pushinteger(L, 4242);
	lua_setfield(L, -2, "max_sessions");

	struct config conf = conf_default();
	T_EXPECT(conf_loadfromtable(L, &conf));
	T_EXPECT(
		conf.listen != NULL &&
		strcmp(conf.listen, "0.0.0.0:1080") == 0);
	T_EXPECT_EQ(conf.loglevel, 5);
	T_EXPECT(conf.timeout == 12.5);
	T_EXPECT(conf.auth_required);
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
	/* boolean field with a non-boolean value */
	{
		lua_State *L = new_conf_table();
		T_CHECK(L != NULL);
		lua_pushinteger(L, 1);
		lua_setfield(L, -2, "auth_required");
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
#endif /* WITH_LUA */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, conf_default_has_expected_values);
	T_RUN_CASE(t, conf_requires_listen);
	T_RUN_CASE(t, conf_rejects_incompatible_modes);
	T_RUN_CASE(t, conf_rejects_timeout_out_of_range);
	T_RUN_CASE(t, conf_rejects_startup_limits_out_of_range);
	T_RUN_CASE(t, conf_rejects_proxy_with_socks5_extensions);
	T_RUN_CASE(t, conf_accepts_valid_configuration);
	T_RUN_CASE(t, conf_warns_small_tcp_buffers);
	T_RUN_CASE(t, conf_rejects_block_global_and_local);
#if WITH_TPROXY
	T_RUN_CASE(t, conf_rejects_http_with_tproxy);
	T_RUN_CASE(t, conf_rejects_forward_with_tproxy);
#endif
#if WITH_RULESET
	T_RUN_CASE(t, conf_warns_ruleset_overrides_proxy);
	T_RUN_CASE(t, conf_rejects_ruleset_with_socks5_bind);
	T_RUN_CASE(t, conf_rejects_ruleset_with_socks5_udp);
#endif
	T_RUN_CASE(t, conf_rejects_auth_required_in_forward_mode);
#if WITH_RULESET
	T_RUN_CASE(t, conf_defers_auth_required_ruleset_check);
#endif
	T_RUN_CASE(t, parseargs_help_returns_false);
	T_RUN_CASE(t, parseargs_resolve_pf_flags);
	T_RUN_CASE(t, parseargs_http_with_address);
	T_RUN_CASE(t, parseargs_http_only);
	T_RUN_CASE(t, parseargs_proxy_and_api);
	T_RUN_CASE(t, parseargs_auth_required);
	T_RUN_CASE(t, parseargs_user_daemonize_color);
	T_RUN_CASE(t, parseargs_timeout);
	T_RUN_CASE(t, parseargs_loglevel);
	T_RUN_CASE(t, parseargs_log_outputs);
	T_RUN_CASE(t, parseargs_block_outbound);
	T_RUN_CASE(t, parseargs_max_sessions);
	T_RUN_CASE(t, parseargs_max_startups);
	T_RUN_CASE(t, parseargs_double_dash_and_unknown);
#if WITH_CARES
	T_RUN_CASE(t, parseargs_nameserver);
#endif
#if WITH_TPROXY
	T_RUN_CASE(t, parseargs_tproxy);
#endif
#if WITH_NETDEVICE
	T_RUN_CASE(t, parseargs_netdev);
#endif
#if WITH_REUSEPORT
	T_RUN_CASE(t, parseargs_reuseport);
#endif
#if WITH_SPLICE
	T_RUN_CASE(t, parseargs_pipe);
#endif
#if WITH_TCP_FASTOPEN
	T_RUN_CASE(t, parseargs_no_fastopen);
#endif
#if WITH_RULESET
	T_RUN_CASE(t, parseargs_ruleset);
	T_RUN_CASE(t, parseargs_dump_config_deprecated);
#endif
	T_RUN_CASE(t, parseargs_forward_flag);
	T_RUN_CASE(t, parseargs_block_multicast_token);
#if WITH_RULESET
	T_RUN_CASE(t, parseargs_config_flag);
	T_RUN_CASE(t, parseargs_config_and_ruleset_mutually_exclusive);
	T_RUN_CASE(t, parseargs_memlimit_negative_clamped);
#endif
#if WITH_LUA
	T_RUN_CASE(t, loadtable_applies_typed_fields);
	T_RUN_CASE(t, loadtable_empty_preserves_defaults);
	T_RUN_CASE(t, loadtable_rejects_wrong_types);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
