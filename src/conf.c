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

		.tcp_keepalive = true,
		.tcp_sndbuf = 0,
		.tcp_rcvbuf = 0,

		.max_sessions = 4096,
		.startup_limit_start = 10,
		.startup_limit_rate = 30,
		.startup_limit_full = 100,
	};
#if HAVE_TCP_NODELAY
	conf.tcp_nodelay = true;
#endif
	return conf;
}

static bool conf_check_range(
	const char *key, const size_t value, const size_t min, const size_t max)
{
	if (value < min || value > max) {
		LOGE_F("config: %s is out of range (%zu - %zu)", key, min, max);
		return false;
	}
	return true;
}

#define RANGE_CHECK(conf, key, min, max)                                       \
	conf_check_range(#key, (conf)->key, min, max)

bool conf_check(const struct config *restrict conf)
{
	const bool range_ok =
		RANGE_CHECK(conf, startup_limit_start, 1, SIZE_MAX) &&
		RANGE_CHECK(conf, startup_limit_rate, 0, 100) &&
		RANGE_CHECK(conf, startup_limit_full, 1, SIZE_MAX) &&
		RANGE_CHECK(
			conf, log_level, LOG_LEVEL_SILENCE, LOG_LEVEL_VERBOSE);
	return range_ok;
}
