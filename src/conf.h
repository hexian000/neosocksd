/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include <stdbool.h>

struct config {
	/* Heap block owning a subset of the string data referenced by const
	 * char * fields below. Other fields may point into argv[] or literals.
	 * Always call free(conf.strings) when discarding a config. */
	char *strings;

	const char *listen;
	const char *forward;
	const char *proxy;
	const char *restapi;
	const char *http_listen;
#if WITH_RULESET
	const char *ruleset;
#endif
#if WITH_LUA
	const char *boot;
#endif
	const char *user_name;
#if WITH_CARES
	const char *nameserver;
#endif
#if WITH_NETDEVICE
	const char *netdev;
#endif
	int loglevel;
	int resolve_pf;
	double timeout;
#if WITH_RULESET
	int memlimit;
#endif

	bool auth_required;
#if WITH_SPLICE
	bool pipe;
#endif
#if WITH_REUSEPORT
	bool reuseport;
#endif
#if WITH_TCP_FASTOPEN
	bool tcp_fastopen;
#endif
#if WITH_TCP_FASTOPEN_CONNECT
	bool tcp_fastopen_connect;
#endif
	bool tcp_nodelay;
	bool tcp_keepalive;
#if WITH_TPROXY
	bool transparent;
#endif
#if WITH_RULESET
	bool traceback;
#endif
	bool socks5_bind;
	bool socks5_udp;
	bool daemonize;
	bool block_loopback;
	bool block_multicast;
	bool block_local;
	bool block_global;
#if WITH_LUA
	bool dump_config;
#endif

	int tcp_sndbuf, tcp_rcvbuf;

	int max_sessions;
	int startup_limit_start;
	int startup_limit_rate;
	int startup_limit_full;
};

struct config conf_default(void);

bool conf_check(const struct config *restrict conf);

/* Parse command line arguments into *conf.
 * On error, logs a message and returns false; the caller should exit. */
bool conf_parseargs(struct config *restrict conf, int argc, char *argv[]);

struct lua_State;

/* Extract config fields from a Lua table at the top of L's stack. Nil fields
 * keep their current value. Returns false on type error. L may be the ruleset
 * VM (cfunc_loadconfig) or a standalone state used for a boot config
 * (conf_loadboot); this function assumes nothing about which. */
bool conf_loadfromtable(
	struct lua_State *restrict L, struct config *restrict conf);

#if WITH_LUA
/* Print the command-line configuration to stdout as a Lua table literal.
 * Returns false on output error. */
bool conf_print(const struct config *restrict conf);

/* Load config fields from a Lua script (`-c`/`--config`) in a standalone Lua
 * state, for builds without the ruleset engine. A `ruleset` field in the
 * returned table is rejected; builds with WITH_RULESET use the
 * ruleset-aware loader in ruleset.c instead, which also accepts one.
 * Returns false on error. */
bool conf_loadboot(struct config *restrict conf, const char *restrict filename);
#endif /* WITH_LUA */

#endif /* CONF_H */
