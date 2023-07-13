#ifndef CONF_H
#define CONF_H

#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct config {
	const char *forward;
#if WITH_NETDEVICE
	const char *netdev;
#endif
	int resolve_pf;
	bool proto_timeout : 1;
#if WITH_REUSEPORT
	bool reuseport : 1;
#endif
#if WITH_FASTOPEN
	bool fastopen : 1;
#endif
#if WITH_TPROXY
	bool transparent : 1;
#endif
	bool traceback : 1;
	double timeout;

	size_t max_sessions;
	size_t startup_limit_start;
	size_t startup_limit_rate;
	size_t startup_limit_full;
};

#endif /* CONF_H */
