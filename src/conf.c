/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "utils/slog.h"
#include "utils/minmax.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct config conf_default(void)
{
	struct config conf = {
		.log_level = LOG_LEVEL_WARNING,
		.resolve_pf = PF_UNSPEC,
		.timeout = 60.0,

		.tcp_nodelay = true,
		.tcp_keepalive = true,
		.tcp_sndbuf = 0,
		.tcp_rcvbuf = 0,

		.max_sessions = 4096,
		.startup_limit_start = 10,
		.startup_limit_rate = 30,
		.startup_limit_full = 100,
	};
#if WITH_TCP_FASTOPEN
	conf.tcp_fastopen = true;
#endif
	return conf;
}

#define RANGE_CHECK(conf, key, min, max)                                       \
	do {                                                                   \
		if ((intmax_t)((conf)->key) < (intmax_t)(min) ||               \
		    (intmax_t)((conf)->key) > (intmax_t)(max)) {               \
			LOGE_F("config: %s is out of range (%s - %s)", #key,   \
			       #min, #max);                                    \
			return false;                                          \
		}                                                              \
	} while (0)

#define RANGE_CHECK_FLOAT(conf, key, min, max)                                 \
	do {                                                                   \
		if (!(((conf)->key) >= (min) && ((conf)->key) <= (max))) {     \
			LOGE_F("config: %s is out of range (%s - %s)", #key,   \
			       #min, #max);                                    \
			return false;                                          \
		}                                                              \
	} while (0)

bool conf_check(const struct config *restrict conf)
{
	RANGE_CHECK_FLOAT(conf, timeout, 5.0, 86400.0);
	RANGE_CHECK(conf, startup_limit_start, 1, INT_MAX);
	RANGE_CHECK(conf, startup_limit_rate, 0, 100);
	RANGE_CHECK(conf, startup_limit_full, 1, INT_MAX);

	if (conf->listen == NULL) {
		LOGE("conf: listen address is not specified");
		return false;
	}
#if WITH_RULESET
	if (conf->ruleset != NULL && conf->forward != NULL) {
		LOGE("conf: specifing ruleset and forward at the same time is ambiguous");
		return false;
	}
#endif
#if WITH_TPROXY
	if (conf->transparent && conf->http) {
		LOGE("tproxy and http cannot be specified at the same time");
		return false;
	}
#endif
	if ((conf->tcp_sndbuf != 0 && conf->tcp_sndbuf < 4096) ||
	    (conf->tcp_rcvbuf != 0 && conf->tcp_rcvbuf < 4096)) {
		LOGW("conf: probably too small tcp buffer");
	}
	return true;
}
