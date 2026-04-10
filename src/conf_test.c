/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <sys/socket.h>

#include <stdlib.h>

static struct config make_valid_conf(void)
{
	struct config conf = conf_default();
	conf.listen = "127.0.0.1:1080";
	return conf;
}

T_DECLARE_CASE(test_conf_default_has_expected_values)
{
	const struct config conf = conf_default();

	T_EXPECT_EQ(conf.log_level, LOG_LEVEL_NOTICE);
	T_EXPECT_EQ(conf.resolve_pf, PF_UNSPEC);
	T_EXPECT_EQ(conf.timeout, 60.0);
	T_EXPECT(conf.tcp_nodelay);
	T_EXPECT(conf.tcp_keepalive);
	T_EXPECT(conf.conn_cache);
	T_EXPECT(conf.block_multicast);
	T_EXPECT_EQ(conf.startup_limit_rate, 30.0);
}

T_DECLARE_CASE(test_conf_requires_listen)
{
	struct config conf = conf_default();

	conf.listen = NULL;
	T_EXPECT(!conf_check(&conf));
}

T_DECLARE_CASE(test_conf_rejects_incompatible_modes)
{
	struct config conf = make_valid_conf();

	conf.forward = "127.0.0.1:8080";
	conf.http = true;
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
	conf.startup_limit_rate = 101.0;
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
	conf.startup_limit_rate = 25.0;
	conf.startup_limit_full = 128;
	conf.tcp_sndbuf = 32768;
	conf.tcp_rcvbuf = 32768;
	T_EXPECT(conf_check(&conf));
}

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
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
