#ifndef CONF_H
#define CONF_H

#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct config {
	const char *listen;
	const char *forward;
	const char *restapi;
	const char *ruleset;
	const char *user_name;
#if WITH_NETDEVICE
	const char *netdev;
#endif
	int log_level;
	int resolve_pf;
	double timeout;

	bool http : 1;
	bool proto_timeout : 1;
#if WITH_REUSEPORT
	bool reuseport : 1;
#endif
#if WITH_TCP_FASTOPEN
	bool tcp_fastopen : 1;
#endif
	bool tcp_nodelay : 1;
	bool tcp_keepalive : 1;
#if WITH_TPROXY
	bool transparent : 1;
#endif
	bool traceback : 1;
	bool daemonize : 1;

	size_t tcp_sndbuf, tcp_rcvbuf;

	size_t max_sessions;
	size_t startup_limit_start;
	size_t startup_limit_rate;
	size_t startup_limit_full;
};

struct config conf_default(void);

bool conf_check(const struct config *conf);

#endif /* CONF_H */
