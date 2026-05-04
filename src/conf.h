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

	int tcp_sndbuf, tcp_rcvbuf;

	int max_sessions;
	int startup_limit_start;
	int startup_limit_rate;
	int startup_limit_full;
};

struct config conf_default(void);

bool conf_check(const struct config *conf);

/* Parse command line arguments into *conf. Stores argc and argv internally
 * for later use by conf_reload(). Loads the -c Lua config file if specified.
 * On error, logs a message and returns false; the caller should exit. */
bool conf_parseargs(struct config *restrict conf, int argc, char *argv[]);

/* Reload *conf from the Lua file specified via -c in conf_parseargs().
 * Resets string fields to their argv-parsed baseline before applying the
 * new Lua values (nil fields revert to command-line originals). Logs
 * appropriate messages. Returns false if no config file was specified or
 * loading failed; conf is unchanged on failure. */
bool conf_reload(struct config *restrict conf);

#endif /* CONF_H */
