/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "utils/slog.h"

#include <sys/socket.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

struct config conf_default(void)
{
	const struct config conf = {
		.log_level = LOG_LEVEL_NOTICE,
		.resolve_pf = PF_UNSPEC,
		.timeout = 60.0,

		.tcp_nodelay = true,
		.tcp_keepalive = true,
		.tcp_sndbuf = 0,
		.tcp_rcvbuf = 0,
#if WITH_TCP_FASTOPEN
		.tcp_fastopen = true,
#endif
#if WITH_TCP_FASTOPEN_CONNECT
		.tcp_fastopen_connect = false,
#endif

		.max_sessions = 0,
		.startup_limit_start = 0,
		.startup_limit_rate = 30,
		.startup_limit_full = 0,
	};
	return conf;
}

static bool range_check_int(
	const char *key, const int value, const int lbound, const int ubound)
{
	if (!(lbound <= value && value <= ubound)) {
		LOGE_F("%s is out of range (%d - %d)", key, lbound, ubound);
		return false;
	}
	return true;
}

static bool range_check_double(
	const char *key, const double value, const double lbound,
	const double ubound)
{
	if (!(lbound <= value && value <= ubound)) {
		LOGE_F("%s is out of range (%g - %g)", key, lbound, ubound);
		return false;
	}
	return true;
}

#define RANGE_CHECK(key, value, lbound, ubound)                                \
	_Generic(value, int                                                    \
		 : range_check_int, double                                     \
		 : range_check_double)(key, value, lbound, ubound)

bool conf_check(const struct config *restrict conf)
{
	if (conf->listen == NULL) {
		LOGE("listen address is not specified");
		return false;
	}
	bool auth_supported = true;
	int proto_flags = 0;
	if (conf->forward != NULL) {
		proto_flags |= 1;
		auth_supported = false;
	}
#if WITH_TPROXY
	if (conf->transparent) {
		proto_flags |= 2;
		auth_supported = false;
	}
#endif
	if (conf->http) {
		proto_flags |= 4;
	}
	if (proto_flags != (proto_flags & -proto_flags)) {
		LOGE("incompatible flags are specified");
		return false;
	}
	if (conf->tcp_sndbuf > 0 && conf->tcp_sndbuf < 16384) {
		LOGW("tcp send buffer may be too small");
	}
	if (conf->tcp_rcvbuf > 0 && conf->tcp_rcvbuf < 16384) {
		LOGW("tcp recv buffer may be too small");
	}
#if WITH_RULESET
	if (conf->ruleset != NULL && conf->proxy != NULL) {
		LOGW("the proxy will be overwritten by ruleset");
	}
#endif
	if (conf->auth_required) {
		if (!auth_supported) {
			LOGE("authentication is not supported in current mode");
			return false;
		}
#if WITH_RULESET
		if (conf->ruleset == NULL) {
			LOGE("ruleset must be enabled for authentication");
			return false;
		}
#endif
	}

	return RANGE_CHECK("timeout", conf->timeout, 5.0, 86400.0) &&
	       RANGE_CHECK(
		       "startup_limit_start", conf->startup_limit_start, 0,
		       conf->startup_limit_full) &&
	       RANGE_CHECK(
		       "startup_limit_rate", conf->startup_limit_rate, 0,
		       100) &&
	       RANGE_CHECK(
		       "startup_limit_full", conf->startup_limit_full,
		       conf->startup_limit_start,
		       conf->max_sessions > 0 ? conf->max_sessions : INT_MAX);
}
