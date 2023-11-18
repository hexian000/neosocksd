/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct config {
	const char *listen;
	const char *forward;
	const char *proxy;
	const char *restapi;
#if WITH_RULESET
	const char *ruleset;
#endif
	const char *user_name;
#if WITH_CARES
	const char *nameserver;
#endif
#if WITH_NETDEVICE
	const char *netdev;
#endif
	int log_level;
	int resolve_pf;
	double timeout;
#if WITH_RULESET
	size_t memlimit;
#endif

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
#if WITH_RULESET
	bool traceback : 1;
#endif
	bool daemonize : 1;

	size_t tcp_sndbuf, tcp_rcvbuf;

	uint32_t max_sessions;
	uint32_t startup_limit_start;
	double startup_limit_rate;
	uint32_t startup_limit_full;
};

struct config conf_default(void);

bool conf_check(const struct config *conf);

#endif /* CONF_H */
