/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file dialer.h
 * @brief Async state-machine dialer: direct TCP or HTTP/SOCKS4A/SOCKS5 proxy chains.
 */

#ifndef DIALER_H
#define DIALER_H

#include "proto/domain.h"
#include "proto/socks.h"
#include "resolver.h"
#include "util.h"

#include "meta/minmax.h"
#include "utils/buffer.h"

#include <ev.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct config;
struct server;

/**
 * @brief Address types supported by the dialer
 */
enum dialaddr_type {
	ATYP_INET,
	ATYP_INET6,
	ATYP_DOMAIN,
};

/**
 * @brief Network address structure supporting IPv4, IPv6, and domain names
 * @details A domain name is `domain.len` bytes and carries no null byte: the
 * resolver and the ruleset binding both take it as a C string, so a name
 * holding one has to be refused where it enters rather than truncated here.
 * Nor any other byte outside printable ASCII: an HTTP hop writes the name into
 * the CONNECT request-line and the Host field, which frame on the space and
 * the CRLF, so a name that cannot be written there fails the dial instead. And
 * `domain.len` is at least 1: the empty string is no host name, and writing it
 * there would leave the request-target without a host at all.
 */
struct dialaddr {
	enum dialaddr_type type;
	uint_least16_t port;
	union {
		struct in_addr in;
		struct in6_addr in6;
		struct domain_name domain;
	};
};

/**
 * @brief Parse a string address into a dialaddr structure
 * @details The address names a destination to dial, and carries no scheme to
 * take a default port from, so the port is explicit and non-zero: RFC 6335 6
 * reserves port 0 and no connection reaches it.
 * @param addr Output dialaddr structure
 * @param s Input string in "host:port" format
 * @param len Length of input string
 * @return true on success, false on parse error
 */
bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s, size_t len);

/**
 * @brief Set dialaddr from a sockaddr structure
 * @param addr Output dialaddr structure
 * @param sa Input sockaddr structure
 * @param len Length of sockaddr structure
 * @return true on success, false if unsupported address family
 */
bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	socklen_t len);

/**
 * @brief Copy dialaddr structure
 * @param dst Destination dialaddr
 * @param src Source dialaddr
 */
void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src);

/**
 * @brief Format dialaddr as string
 * @param s Output buffer (may be NULL if maxlen is 0)
 * @param maxlen Maximum buffer size (0 to compute length only)
 * @param addr Input dialaddr structure
 * @return Number of characters that would be written, or -1 on error
 */
int dialaddr_format(
	char *restrict s, size_t maxlen, const struct dialaddr *restrict addr);

/**
 * @brief Maximum length, excluding the NUL, of a dialaddr formatted by
 * dialaddr_format() as "host:port": a max-length domain plus ":65535" (the
 * IPv4/IPv6 forms are shorter). Size a buffer as DIALADDR_STRLEN + 1.
 */
#define DIALADDR_STRLEN (FQDN_MAX_LENGTH + CONSTSTRLEN(":65535"))

/**
 * @brief Maximum length, excluding the NUL, of a proxy request formatted by
 * format_proxyreq() as "scheme://host:port": the longest proxy scheme
 * ("socks4a"), "://", and a max-length dialaddr. Size a buffer as
 * PROXYREQ_STRLEN + 1.
 */
#define PROXYREQ_STRLEN (CONSTSTRLEN("socks4a://") + DIALADDR_STRLEN)

/**
 * @brief Supported proxy protocols
 */
enum proxy_protocol {
	/** HTTP CONNECT proxy. */
	PROTO_HTTP,
	PROTO_SOCKS4A,
	PROTO_SOCKS5,

	PROTO_MAX,
};

/** @brief Dialer error codes; use dialer_strerror() for descriptions */
enum dialer_error {
	/** No error, operation successful. */
	DIALER_OK = 0,
	/** Operation cancelled by user. */
	DIALER_CANCELLED,
	/** System error, check syserr for errno. */
	DIALER_ERR_SYSTEM,
	/** DNS resolution failed. */
	DIALER_ERR_RESOLVE,
	/** TCP connection failed. */
	DIALER_ERR_CONNECT,
	/** Proxy protocol error from a malformed response. */
	DIALER_ERR_PROXY_PROTO,
	/** Proxy authentication failed. */
	DIALER_ERR_PROXY_AUTH,
	/** Proxy refused the connection request. */
	DIALER_ERR_PROXY_REFUSED,
	/** Request rejected by the proxy, for example by policy. */
	DIALER_ERR_PROXY_REJECT,
	/** Unexpected end of connection. */
	DIALER_ERR_EOF,
	/** Connection blocked by local policy. */
	DIALER_ERR_BLOCKED,
	/** The request names an address no protocol message can carry, or a
	 * port no connection reaches. */
	DIALER_ERR_BADADDR,

	DIALER_ERR_MAX,
};

/**
 * @brief Get human-readable error description
 * @param err Dialer error code
 * @return Static string describing the error
 */
const char *dialer_strerror(enum dialer_error err);

/** @brief String names for proxy protocols */
extern const char *const proxy_protocol_str[PROTO_MAX];

/**
 * @brief Proxy server request configuration
 */
struct proxyreq {
	enum proxy_protocol proto;
	struct dialaddr addr;
	char *username, *password;
	/* Storage for credential strings */
	char credential[512];
};

/**
 * @brief Complete dial request including target address and proxy chain
 */
struct dialreq {
	struct dialaddr addr;
	size_t num_proxy;
	/* Allocated proxy[] slots; dialreq_addproxy() appends up to this many */
	size_t num_proxy_max;
	struct proxyreq proxy[];
};

/**
 * @brief Create a new dial request structure
 * @param base Base dial request to copy proxies from (may be NULL)
 * @param num_proxy Number of additional proxy slots to allocate
 * @return Allocated dialreq structure, or NULL on memory allocation failure
 */
struct dialreq *dialreq_new(const struct dialreq *base, size_t num_proxy);

/**
 * @brief Add a proxy to a dial request
 * @details The URI's port is optional: an absent or empty port subcomponent
 * takes the scheme's default (RFC 3986 3.2.3, RFC 9110 4.2.1).
 * @param req Dial request to modify
 * @param proxy_uri Proxy URI string (e.g., "http://proxy:8080")
 * @param urilen Length of proxy URI string
 * @return true on success, false on parse error or when proxy[] is full
 */
bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	size_t urilen);

/**
 * @brief Parse address and proxy chain from strings
 * @param addr Target address string; NULL or CONF_FORWARD_ANY for wildcard
 * @param csv Comma-separated list of proxy URIs (may be NULL for direct connection)
 * @return Allocated dialreq structure, or NULL on error
 */
struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv);

/**
 * @brief Format dial request as human-readable string
 * @param s Output buffer (may be NULL if maxlen is 0)
 * @param maxlen Maximum buffer size (0 to compute length only)
 * @param r Dial request to format
 * @return Number of characters that would be written, or -1 on error
 */
int dialreq_format(
	char *restrict s, size_t maxlen, const struct dialreq *restrict r);

/**
 * @brief Free a dial request structure
 * @param req Dial request to free
 */
void dialreq_free(struct dialreq *req);

/**
 * @brief Replace *req with a freshly parsed dial request, freeing the old one
 * @param req Pointer to the dial request to replace; left unchanged on failure
 * @param addr Target address string; NULL or CONF_FORWARD_ANY for wildcard
 * @param csv Comma-separated list of proxy URIs (may be NULL for direct connection)
 * @return true on success, false if the new dial request could not be parsed
 */
bool dialreq_replace(
	struct dialreq **restrict req, const char *restrict addr,
	const char *restrict csv);

/**
 * @brief Headroom for an upstream proxy's HTTP CONNECT response: the status
 * line plus every response header, with one byte left over for the terminator
 * the parser writes after them, must fit here, or the dial fails as "header too
 * long". Tunnel bytes queued behind a complete header block do not count
 * against it. A conforming proxy can send well over 1 KiB --
 * a long Proxy-Authenticate challenge on a 407, Via/X-Cache stacks, portal
 * Set-Cookie -- so this matches the 8 KiB header block used elsewhere for HTTP
 * connections (proto/http.h HTTP_MAX_ENTITY) rather than the request maxima.
 */
#define DIALER_HTTP_RSP_MAXLEN 8192

/**
 * @brief Size of the dialer receive buffer: large enough for the largest
 * upstream proxy handshake response. That is the HTTP CONNECT response header
 * block (DIALER_HTTP_RSP_MAXLEN); SOCKS4a/5 responses are bounded well below
 * SOCKS_REQ_MAXLEN, kept here so the buffer never shrinks below either.
 */
#define DIALER_RBUF_SIZE MAX(DIALER_HTTP_RSP_MAXLEN, SOCKS_REQ_MAXLEN)

/**
 * @brief Callback function for dialer completion
 */
struct dialer_cb {
	void (*func)(struct ev_loop *loop, void *data, const int fd);
	void *data;
};

/** @brief Progress of a dial through the dialer state machine */
enum dialer_state {
	/** Initial state, not yet started. */
	DIALER_STATE_INIT,
	/** Resolving the domain name to an IP address. */
	DIALER_STATE_RESOLVE,
	/** Establishing the TCP connection. */
	DIALER_STATE_CONNECT,
	/** First phase of the proxy handshake. */
	DIALER_STATE_HANDSHAKE1,
	/** Second phase of the proxy handshake. */
	DIALER_STATE_HANDSHAKE2,
	/** Third phase of the proxy handshake. */
	DIALER_STATE_HANDSHAKE3,
	/** Connection established or failed. */
	DIALER_STATE_DONE,
};

/** @brief Dialer state machine */
struct dialer {
	const struct dialreq *req;
	const struct config *conf;
	struct resolver *resolver;
	struct resolve_query *resolve_query;
	size_t jump;
	enum dialer_state state;
	/* High-level error code */
	enum dialer_error err;
	/* System errno; set for DIALER_ERR_SYSTEM and DIALER_ERR_CONNECT, 0
	 * otherwise */
	int syserr;
	ev_io w_socket;
	int dialed_fd;
	/* Addresses to try in resolver order and their connect sockets,
	 * staggered per RFC 8305; live only in DIALER_STATE_CONNECT. The winner
	 * becomes dialed_fd (direct) or moves to w_socket (proxied handshake);
	 * the losers are closed. */
	union sockaddr_max addr[RESOLVE_MAX_ADDR];
	size_t num_addr, next_addr, num_inflight;
	ev_io w_attempt[RESOLVE_MAX_ADDR];
	ev_timer w_delay;
	ev_watcher w_finish;
	struct dialer_cb finish_cb;
	uint_least64_t *byt_sent, *byt_recv;
	/* Timestamp when dialer_do() was called (clock_monotonic_ns) */
	int_least64_t start_ns;
	/* Server for recording connect_ns; may be NULL */
	struct server *server;
	unsigned char *next;
	struct {
		BUFFER_HDR;
		unsigned char data[DIALER_RBUF_SIZE];
	} rbuf;
};

/**
 * @brief Initialize a dialer structure
 * @param d Dialer structure to initialize
 * @param callback Completion callback configuration
 */
void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *byt_sent, uint_least64_t *byt_recv);

/**
 * @brief Start a dial operation
 * @param d Initialized dialer structure
 * @param loop libev event loop
 * @param req Dial request specifying target and proxy chain
 * @param conf Configuration (ingress/egress policy, socket options, etc.)
 * @param resolver DNS resolver
 * @param server Server instance for recording connect_ns; may be NULL
 */
void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver,
	struct server *server);

/**
 * @brief Cancel an ongoing dial operation
 * @param d Active dialer structure
 * @param loop libev event loop
 */
void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop);

/**
 * @brief Describe a dialer's failure, appending the OS error when one is set.
 * @param buf Caller-provided scratch buffer.
 * @param bufsize Size of @p buf.
 * @param d Dialer whose err/syserr to describe.
 * @return @p buf when a syserr was appended, otherwise a static
 *         dialer_strerror() string (@p buf then left untouched).
 */
static inline const char *dialer_errorstr(
	char *buf, const size_t bufsize, const struct dialer *restrict d)
{
	const char *const errstr = dialer_strerror(d->err);
	if (d->syserr == 0) {
		return errstr;
	}
	(void)snprintf(
		buf, bufsize, "%s (%d) %s", errstr, d->syserr,
		strerror(d->syserr));
	return buf;
}

#endif /* DIALER_H */
