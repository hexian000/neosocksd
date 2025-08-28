/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file dialer.h
 * @brief Network dialer for establishing connections through proxy chains
 * 
 * This module provides functionality for establishing network connections
 * either directly or through a chain of proxy servers. It supports multiple
 * proxy protocols including HTTP CONNECT, SOCKS4A, and SOCKS5.
 * 
 * The dialer uses an asynchronous state machine to handle connection
 * establishment and proxy handshakes, integrating with libev for event-driven
 * operation.
 */

#ifndef DIALER_H
#define DIALER_H

#include "proto/domain.h"
#include "proto/socks.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/minmax.h"

#include <ev.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
 */
struct dialaddr {
	enum dialaddr_type type;
	uint16_t port;
	union {
		struct in_addr in;
		struct in6_addr in6;
		struct domain_name domain;
	};
};

/**
 * @brief Parse a string address into a dialaddr structure
 * @param addr Output dialaddr structure
 * @param s Input string in "host:port" format
 * @param len Length of input string
 * @return true on success, false on parse error
 */
bool dialaddr_parse(struct dialaddr *addr, const char *s, size_t len);

/**
 * @brief Set dialaddr from a sockaddr structure
 * @param addr Output dialaddr structure
 * @param sa Input sockaddr structure
 * @param len Length of sockaddr structure
 * @return true on success, false if unsupported address family
 */
bool dialaddr_set(
	struct dialaddr *addr, const struct sockaddr *sa, socklen_t len);

/**
 * @brief Copy dialaddr structure
 * @param dst Destination dialaddr
 * @param src Source dialaddr
 */
void dialaddr_copy(struct dialaddr *dst, const struct dialaddr *src);

/**
 * @brief Format dialaddr as string
 * @param s Output buffer
 * @param maxlen Maximum buffer size
 * @param addr Input dialaddr structure
 * @return Number of characters written, or -1 on error
 */
int dialaddr_format(char *s, size_t maxlen, const struct dialaddr *addr);

/**
 * @brief Supported proxy protocols
 */
enum proxy_protocol {
	PROTO_HTTP, /**< HTTP CONNECT proxy */
	PROTO_SOCKS4A,
	PROTO_SOCKS5,

	PROTO_MAX,
};

/** @brief String names for proxy protocols */
extern const char *proxy_protocol_str[PROTO_MAX];

/**
 * @brief Proxy server request configuration
 */
struct proxyreq {
	enum proxy_protocol proto;
	struct dialaddr addr;
	char *username, *password;
	char credential[512]; /**< Storage for credential strings */
};

/**
 * @brief Complete dial request including target address and proxy chain
 */
struct dialreq {
	struct dialaddr addr;
	size_t num_proxy;
	struct proxyreq proxy[];
};

/**
 * @brief Create a new dial request structure
 * @param num_proxy Number of proxy slots to allocate
 * @return Allocated dialreq structure, or NULL on memory allocation failure
 */
struct dialreq *dialreq_new(size_t num_proxy);

/**
 * @brief Add a proxy to a dial request
 * @param req Dial request to modify
 * @param proxy_uri Proxy URI string (e.g., "http://proxy:8080")
 * @param urilen Length of proxy URI string
 * @return true on success, false on parse error
 */
bool dialreq_addproxy(struct dialreq *req, const char *proxy_uri, size_t urilen);

/**
 * @brief Parse address and proxy chain from strings
 * @param addr Target address string (may be NULL for wildcard)
 * @param csv Comma-separated list of proxy URIs (may be NULL for direct connection)
 * @return Allocated dialreq structure, or NULL on error
 */
struct dialreq *dialreq_parse(const char *addr, const char *csv);

/**
 * @brief Format dial request as human-readable string
 * @param s Output buffer
 * @param maxlen Maximum buffer size
 * @param r Dial request to format
 * @return Number of characters written
 */
int dialreq_format(char *s, size_t maxlen, const struct dialreq *r);

/**
 * @brief Free a dial request structure
 * @param req Dial request to free
 */
void dialreq_free(struct dialreq *req);

/** @brief Size of dialer receive buffer (large enough for any protocol response) */
#define DIALER_RBUF_SIZE                                                       \
	MAX(CONSTSTRLEN("CONNECT ") + FQDN_MAX_LENGTH +                        \
		    CONSTSTRLEN(":65535 HTTP/1.1\r\n\r\n"),                    \
	    SOCKS_REQ_MAXLEN)

/**
 * @brief Callback function for dialer completion
 */
struct dialer_cb {
	void (*func)(struct ev_loop *loop, void *data, const int fd);
	void *data;
};

/**
 * @brief Dialer state machine structure
 * 
 * This structure maintains the state of an ongoing dial operation,
 * including proxy chain traversal and protocol handshakes.
 */
struct dialer {
	const struct dialreq *req;
	struct resolve_query *resolve_query;
	size_t jump;
	int state;
	int syserr;
	ev_io w_socket;
	int dialed_fd;
	ev_watcher w_finish;
	struct dialer_cb finish_cb;
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
void dialer_init(struct dialer *d, const struct dialer_cb *callback);

/**
 * @brief Start a dial operation
 * @param d Initialized dialer structure
 * @param loop libev event loop
 * @param req Dial request specifying target and proxy chain
 */
void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req);

/**
 * @brief Cancel an ongoing dial operation
 * @param d Active dialer structure
 * @param loop libev event loop
 */
void dialer_cancel(struct dialer *d, struct ev_loop *loop);

#endif /* DIALER_H */
