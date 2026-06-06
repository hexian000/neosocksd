/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>
#if WITH_LUA
#include <stdio.h>
#include <unistd.h>
#endif

static struct config make_valid_conf(void)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	return conf;
}

T_DECLARE_CASE(test_conf_default_has_expected_values)
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

T_DECLARE_CASE(test_conf_requires_listen)
{
	struct config conf = conf_default();

	conf.listen = NULL;
	T_EXPECT(!conf_check(&conf));
	conf.http_listen = "127.0.0.1:8080";
	T_EXPECT(conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_incompatible_modes)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:8080";
	conf.http_listen = "127.0.0.1:8081";
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_timeout_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.timeout = 4.9;
	T_EXPECT(!conf_check(&conf));
	conf.timeout = 86400.1;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_startup_limits_out_of_range)
{
	struct config conf = make_valid_conf();

	conf.startup_limit_start = 4;
	conf.startup_limit_full = 3;
	T_EXPECT(!conf_check(&conf));

	conf = make_valid_conf();
	conf.startup_limit_rate = 101;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_proxy_with_socks5_extensions)
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

T_DECLARE_CASE(test_conf_accepts_valid_configuration)
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

T_DECLARE_CASE(test_conf_warns_small_tcp_buffers)
{
	struct config conf = make_valid_conf();

	conf.tcp_sndbuf = 1024;
	conf.tcp_rcvbuf = 4096;
	T_EXPECT(conf_check(&conf)); /* warns but remains valid */
}

T_DECLARE_CASE(test_conf_rejects_block_global_and_local)
{
	struct config conf = make_valid_conf();

	conf.block_global = true;
	conf.block_local = true;
	T_EXPECT(!conf_check(&conf));
}

#if WITH_TPROXY
T_DECLARE_CASE(test_conf_rejects_http_with_tproxy)
{
	struct config conf = make_valid_conf();

	conf.http_listen = "127.0.0.1:8080";
	conf.transparent = true;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_forward_with_tproxy)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:9999";
	conf.transparent = true;
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_TPROXY */

#if WITH_RULESET
T_DECLARE_CASE(test_conf_warns_ruleset_overrides_proxy)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.proxy = "socks5://127.0.0.1:1080";
	T_EXPECT(conf_check(&conf)); /* just a warning, still valid */
}

T_DECLARE_CASE(test_conf_rejects_ruleset_with_socks5_bind)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.socks5_bind = true;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_ruleset_with_socks5_udp)
{
	struct config conf = make_valid_conf();

	conf.ruleset = "ruleset.lua";
	conf.socks5_udp = true;
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_RULESET */

T_DECLARE_CASE(test_conf_rejects_auth_required_in_forward_mode)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:8080";
	conf.auth_required = true;
	T_EXPECT(!conf_check(&conf));
}

#if WITH_RULESET
T_DECLARE_CASE(test_conf_rejects_auth_required_without_ruleset)
{
	struct config conf = make_valid_conf();

	conf.auth_required = true;
	/* ruleset == NULL with auth_required is rejected when WITH_RULESET */
	T_EXPECT(!conf_check(&conf));
}
#endif /* WITH_RULESET */

/* conf_parseargs tests */

T_DECLARE_CASE(test_parseargs_help_returns_false)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "--help" };

	T_EXPECT(!conf_parseargs(&conf, 2, argv));
}

T_DECLARE_CASE(test_parseargs_resolve_pf_flags)
{
	struct config conf = conf_default();
	char *argv4[] = { "conf_test", "-4", "-l", "127.0.0.1:1080" };

	T_EXPECT(conf_parseargs(&conf, 4, argv4));
	T_EXPECT_EQ(conf.resolve_pf, PF_INET);

	char *argv6[] = { "conf_test", "-6", "-l", "127.0.0.1:1080" };
	T_EXPECT(conf_parseargs(&conf, 4, argv6));
	T_EXPECT_EQ(conf.resolve_pf, PF_INET6);
}

T_DECLARE_CASE(test_parseargs_http_with_address)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "0.0.0.0:1080", "--http",
			 "0.0.0.0:8080" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.http_listen, "0.0.0.0:8080");
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:1080");
}

T_DECLARE_CASE(test_parseargs_http_only)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "0.0.0.0:8080", "--http" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.listen == NULL);
	T_EXPECT_STREQ(conf.http_listen, "0.0.0.0:8080");
}

T_DECLARE_CASE(test_parseargs_proxy_and_api)
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

T_DECLARE_CASE(test_parseargs_auth_required)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080",
			 "--auth-required" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.auth_required);
}

T_DECLARE_CASE(test_parseargs_user_daemonize_color)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test",
			 "-l",
			 "127.0.0.1:1080",
			 "-u",
			 "nobody:nogroup",
			 "-d",
			 "-C",
			 "--enable-socks5-bind",
			 "--enable-socks5-udp" };

	T_EXPECT(conf_parseargs(&conf, 9, argv));
	T_EXPECT_STREQ(conf.user_name, "nobody:nogroup");
	T_EXPECT(conf.daemonize);
	T_EXPECT(conf.socks5_bind);
	T_EXPECT(conf.socks5_udp);
}

T_DECLARE_CASE(test_parseargs_timeout)
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

T_DECLARE_CASE(test_parseargs_loglevel)
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

T_DECLARE_CASE(test_parseargs_block_outbound)
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

T_DECLARE_CASE(test_parseargs_max_sessions)
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

T_DECLARE_CASE(test_parseargs_max_startups)
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

T_DECLARE_CASE(test_parseargs_double_dash_and_unknown)
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

#if WITH_CARES
T_DECLARE_CASE(test_parseargs_nameserver)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--nameserver",
			 "8.8.8.8" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.nameserver, "8.8.8.8");
}
#endif /* WITH_CARES */

#if WITH_TPROXY
T_DECLARE_CASE(test_parseargs_tproxy)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--tproxy" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.transparent);
}
#endif /* WITH_TPROXY */

#if WITH_NETDEVICE
T_DECLARE_CASE(test_parseargs_netdev)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "-i", "eth0" };

	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.netdev, "eth0");
}
#endif /* WITH_NETDEVICE */

#if WITH_REUSEPORT
T_DECLARE_CASE(test_parseargs_reuseport)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--reuseport" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.reuseport);
}
#endif /* WITH_REUSEPORT */

#if WITH_SPLICE
T_DECLARE_CASE(test_parseargs_pipe)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--pipe" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(conf.pipe);
}
#endif /* WITH_SPLICE */

#if WITH_TCP_FASTOPEN
T_DECLARE_CASE(test_parseargs_no_fastopen)
{
	struct config conf = conf_default();
	char *argv[] = { "conf_test", "-l", "127.0.0.1:1080", "--no-fastopen" };

	T_EXPECT(conf_parseargs(&conf, 4, argv));
	T_EXPECT(!conf.tcp_fastopen);
}
#endif /* WITH_TCP_FASTOPEN */

#if WITH_RULESET
T_DECLARE_CASE(test_parseargs_ruleset)
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

#if WITH_LUA
#if 0 /* boot config tests require the removed conf_loadfile */
/* Write content to a temporary file and return the fd; caller owns fd. */
static int write_tempfile(char *restrict tmpl, const char *restrict content)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	const size_t len = strlen(content);
	if ((size_t)write(fd, content, len) != len) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	close(fd);
	return 0;
}
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return { listen = '0.0.0.0:9999' }") ==
		0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test", "-c", path, "-l", "old:1080",
	};
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:9999");
	free(conf.strings);
	unlink(path);
}

T_DECLARE_CASE(test_boot_nil_field_preserves_cli_value)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return { listen = '0.0.0.0:1080' }") ==
		0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test", "-c", path, "-f", "kept:8080",
	};
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.forward, "kept:8080");
	free(conf.strings);
	unlink(path);
}

T_DECLARE_CASE(test_boot_unknown_fields_ignored)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path,
			"return { listen = '0.0.0.0:1080', _unknown_ = true }") ==
		0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(conf_parseargs(&conf, 3, argv));
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:1080");
	free(conf.strings);
	unlink(path);
}

T_DECLARE_CASE(test_boot_type_error_fails)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return { listen = 42 }") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(!conf_parseargs(&conf, 3, argv));
	unlink(path);
}

T_DECLARE_CASE(test_boot_returns_nontable_fails)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return 'oops'") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(!conf_parseargs(&conf, 3, argv));
	unlink(path);
}

T_DECLARE_CASE(test_boot_runtime_error_fails)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "error('intentional')") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(!conf_parseargs(&conf, 3, argv));
	unlink(path);
}

T_DECLARE_CASE(test_boot_varargs_visible)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path, "local argv = { ... }\n"
			      "assert(argv[1] == '-c', 'argv[1]')\n"
			      "assert(argv[3] == '-l', 'argv[3]')\n"
			      "assert(argv[4] == '0.0.0.0:1080', 'argv[4]')\n"
			      "assert(#argv == 4, '#argv')\n"
			      "return { listen = argv[4] }") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test", "-c", path, "-l", "0.0.0.0:1080",
	};
	T_EXPECT(conf_parseargs(&conf, 5, argv));
	T_EXPECT_STREQ(conf.listen, "0.0.0.0:1080");
	free(conf.strings);
	unlink(path);
}

T_DECLARE_CASE(test_boot_overrides_numeric_fields)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(
			path, "return { loglevel = 3, timeout = 120.0,"
			      " max_sessions = 512 }") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(conf_parseargs(&conf, 3, argv));
	T_EXPECT_EQ(conf.loglevel, 3);
	T_EXPECT_EQ(conf.timeout, 120.0);
	T_EXPECT_EQ(conf.max_sessions, 512);
	unlink(path);
}

T_DECLARE_CASE(test_boot_overrides_bool_fields)
{
	char path[] = "/tmp/boot_conf_test_XXXXXX";
	T_CHECK(write_tempfile(path, "return { daemonize = true }") == 0);
	struct config conf = conf_default();
	char *argv[] = {
		"conf_test",
		"-c",
		path,
	};
	T_EXPECT(conf_parseargs(&conf, 3, argv));
	T_EXPECT(conf.daemonize);
	unlink(path);
}

T_DECLARE_CASE(test_dump_config)
{
	/* Redirect stdout to a temp file so conf_print output is captured.
	 * The testing framework uses stderr, so T_EXPECT macros still work. */
	(void)fflush(stdout);
	const int saved_stdout = dup(STDOUT_FILENO);
	T_CHECK(saved_stdout >= 0);
	FILE *tmp = tmpfile();
	T_CHECK(tmp != NULL);
	T_CHECK(dup2(fileno(tmp), STDOUT_FILENO) >= 0);

	struct config conf = conf_default();
	/* listen string with backslash, double-quote, and a control char
	 * to exercise all branches in lutil_printstring */
	char special_listen[] = "a\\\"b\x01";
	char *argv[] = { "conf_test", "-l", special_listen, "--dump-config" };
	const bool ok = conf_parseargs(&conf, 4, argv);

	(void)fflush(stdout);
	(void)dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdout);

	T_EXPECT(ok);
	rewind(tmp);
	char buf[32] = { 0 };
	T_CHECK(fgets(buf, sizeof(buf), tmp) != NULL);
	T_EXPECT_STREQ(buf, "return {\n");
	(void)fclose(tmp);
}
#endif /* 0 */
#endif /* WITH_LUA */

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, test_conf_default_has_expected_values);
	T_RUN_CASE(t, test_conf_requires_listen);
	T_RUN_CASE(t, test_conf_rejects_incompatible_modes);
	T_RUN_CASE(t, test_conf_rejects_timeout_out_of_range);
	T_RUN_CASE(t, test_conf_rejects_startup_limits_out_of_range);
	T_RUN_CASE(t, test_conf_rejects_proxy_with_socks5_extensions);
	T_RUN_CASE(t, test_conf_accepts_valid_configuration);
	T_RUN_CASE(t, test_conf_warns_small_tcp_buffers);
	T_RUN_CASE(t, test_conf_rejects_block_global_and_local);
#if WITH_TPROXY
	T_RUN_CASE(t, test_conf_rejects_http_with_tproxy);
	T_RUN_CASE(t, test_conf_rejects_forward_with_tproxy);
#endif
#if WITH_RULESET
	T_RUN_CASE(t, test_conf_warns_ruleset_overrides_proxy);
	T_RUN_CASE(t, test_conf_rejects_ruleset_with_socks5_bind);
	T_RUN_CASE(t, test_conf_rejects_ruleset_with_socks5_udp);
#endif
	T_RUN_CASE(t, test_conf_rejects_auth_required_in_forward_mode);
#if WITH_RULESET
	T_RUN_CASE(t, test_conf_rejects_auth_required_without_ruleset);
#endif
	T_RUN_CASE(t, test_parseargs_help_returns_false);
	T_RUN_CASE(t, test_parseargs_resolve_pf_flags);
	T_RUN_CASE(t, test_parseargs_http_with_address);
	T_RUN_CASE(t, test_parseargs_http_only);
	T_RUN_CASE(t, test_parseargs_proxy_and_api);
	T_RUN_CASE(t, test_parseargs_auth_required);
	T_RUN_CASE(t, test_parseargs_user_daemonize_color);
	T_RUN_CASE(t, test_parseargs_timeout);
	T_RUN_CASE(t, test_parseargs_loglevel);
	T_RUN_CASE(t, test_parseargs_block_outbound);
	T_RUN_CASE(t, test_parseargs_max_sessions);
	T_RUN_CASE(t, test_parseargs_max_startups);
	T_RUN_CASE(t, test_parseargs_double_dash_and_unknown);
#if WITH_CARES
	T_RUN_CASE(t, test_parseargs_nameserver);
#endif
#if WITH_TPROXY
	T_RUN_CASE(t, test_parseargs_tproxy);
#endif
#if WITH_NETDEVICE
	T_RUN_CASE(t, test_parseargs_netdev);
#endif
#if WITH_REUSEPORT
	T_RUN_CASE(t, test_parseargs_reuseport);
#endif
#if WITH_SPLICE
	T_RUN_CASE(t, test_parseargs_pipe);
#endif
#if WITH_TCP_FASTOPEN
	T_RUN_CASE(t, test_parseargs_no_fastopen);
#endif
#if WITH_RULESET
	T_RUN_CASE(t, test_parseargs_ruleset);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
