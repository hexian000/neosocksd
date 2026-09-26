/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include <stdbool.h>

/* The `-f' address that names no destination: forward mode with the ruleset
 * choosing each connection's target. Only a configured address spells it. */
#define CONF_FORWARD_ANY ":"

struct config {
	/* Heap block owning a subset of the string data referenced by const
	 * char * fields below. Other fields may point into argv[] or literals.
	 * Always call free(conf.strings) when discarding a config. */
	char *strings;

	const char *listen;
	/* forward-mode destination, or CONF_FORWARD_ANY */
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
#if WITH_TCP_KEEPALIVE_PARAMS
	/* 0 keeps the system default */
	int tcp_keepidle, tcp_keepintvl, tcp_keepcnt;
#endif

	int max_sessions;
	int startup_limit_start;
	int startup_limit_rate;
	int startup_limit_full;
#if WITH_THREADS
	/* number of dedicated I/O worker threads (>= 1); ignored without
	 * thread support, where transfers run on the main loop */
	int workers;
#endif
};

struct config conf_default(void);

bool conf_check(const struct config *restrict conf);

/* Report valid settings that interact in a non-obvious way. Separate from
 * conf_check because the interaction depends on whether a ruleset was actually
 * installed, which struct config cannot express: it holds only the `-r`
 * filename, while a `-c` boot config installs a ruleset without setting it.
 * Call once, after the ruleset is settled. */
void conf_advise(const struct config *restrict conf, bool has_ruleset);

/* Parse command line arguments into *conf.
 * On error, logs a message and returns false; the caller should exit. */
bool conf_parseargs(struct config *restrict conf, int argc, char *argv[]);

#if WITH_LUA
struct lua_State;

/* Extract config fields from a Lua table at the top of L's stack, checking
 * their domains; nil fields keep their current value. Returns false on a bad
 * field, but may also raise, so call it from a protected frame. L may be the
 * ruleset VM (cfunc_loadconfig) or a standalone state used for a boot config
 * (conf_loadboot); this function assumes nothing about which. */
bool conf_loadfromtable(
	struct lua_State *restrict L, struct config *restrict conf);

/* conf_loadfromtable for a reload into the config the running server was
 * started with. The staged config must also pass conf_check, leave unchanged
 * every field the server applies only at startup (the listener addresses,
 * `transparent', `reuseport', `tcp_fastopen', `workers', and whether `forward'
 * is set), and not require authentication unless has_ruleset, which tells
 * whether a ruleset is installed once the load commits. A table that fails
 * any of these leaves conf unchanged. */
bool conf_reloadfromtable(
	struct lua_State *restrict L, struct config *restrict conf,
	bool has_ruleset);

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
