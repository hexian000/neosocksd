#include "conf.h"
#include "utils/slog.h"
#include "utils/minmax.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct config conf_default(void)
{
	struct config conf = {
		.log_level = LOG_LEVEL_INFO,
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
	RANGE_CHECK(conf, log_level, LOG_LEVEL_SILENCE, LOG_LEVEL_VERBOSE);
	return true;
}
