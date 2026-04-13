/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include <stdbool.h>

struct config {
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
	int log_level;
	int resolve_pf;
	double timeout;
#if WITH_RULESET
	int memlimit;
#endif

	bool auth_required;
	bool bidir_timeout;
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
	bool conn_cache;
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
	double startup_limit_rate;
	int startup_limit_full;
};

struct config conf_default(void);

bool conf_check(const struct config *conf);

#if WITH_LUA
#include <stddef.h>

/* Tag for a struct config field's C type. */
enum conf_type {
	CONF_STRING, /* const char * */
	CONF_INT, /* int */
	CONF_DOUBLE, /* double */
	CONF_BOOL, /* bool */
};

/* Descriptor for one named field of struct config.
 * Used to drive both conf_loadfile and conf_savefile. */
struct metaconfig {
	const char *key; /* Lua table key */
	enum conf_type type;
	size_t offset; /* offsetof(struct config, <field>) */
};

/* Load configuration from a Lua boot script.
 * The script receives the command-line arguments (excluding argv[0])
 * as a global `arg` table (1-indexed, with arg.n = argc).
 * Fields in the returned table overwrite the corresponding fields in *conf.
 * Unknown fields are silently ignored. Returns false on error. */
bool conf_loadfile(
	const char *restrict path, int argc,
	const char *const restrict argv[const restrict],
	struct config *restrict conf);

/* Print the current configuration as a pretty-printed Lua table to stdout.
 * Returns false on write error. */
bool conf_print(const struct config *restrict conf);
#endif /* WITH_LUA */

#endif /* CONF_H */
