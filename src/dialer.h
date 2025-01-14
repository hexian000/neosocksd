/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

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

enum dialaddr_type {
	ATYP_INET,
	ATYP_INET6,
	ATYP_DOMAIN,
};

struct dialaddr {
	enum dialaddr_type type;
	uint16_t port;
	union {
		struct in_addr in;
		struct in6_addr in6;
		struct domain_name domain;
	};
};

bool dialaddr_parse(struct dialaddr *addr, const char *s, size_t len);
void dialaddr_copy(struct dialaddr *dst, const struct dialaddr *src);
int dialaddr_format(char *s, size_t maxlen, const struct dialaddr *addr);

enum proxy_protocol {
	PROTO_HTTP,
	PROTO_SOCKS4A,
	PROTO_SOCKS5,

	PROTO_MAX,
};
extern const char *proxy_protocol_str[PROTO_MAX];

struct proxyreq {
	enum proxy_protocol proto;
	struct dialaddr addr;
	char *username, *password;
	char credential[512];
};

struct dialreq {
	struct dialaddr addr;
	size_t num_proxy;
	struct proxyreq proxy[];
};

struct dialreq *dialreq_new(size_t num_proxy);
bool dialreq_addproxy(struct dialreq *r, const char *proxy_uri, size_t urilen);
struct dialreq *dialreq_parse(const char *addr, const char *csv);
int dialreq_format(char *s, size_t maxlen, const struct dialreq *r);
void dialreq_free(struct dialreq *r);

#define DIALER_RBUF_SIZE                                                       \
	MAX(CONSTSTRLEN("CONNECT ") + FQDN_MAX_LENGTH +                        \
		    CONSTSTRLEN(":65535 HTTP/1.1\r\n\r\n"),                    \
	    SOCKS_REQ_MAXLEN)

struct dialer {
	struct event_cb done_cb;
	const struct dialreq *req;
	struct resolve_query *resolve_query;
	size_t jump;
	int state;
	int syserr;
	struct ev_io w_socket;
	unsigned char *next;
	struct {
		BUFFER_HDR;
		unsigned char data[DIALER_RBUF_SIZE];
	} rbuf;
};

void dialer_init(struct dialer *d, const struct event_cb *cb);

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req);

void dialer_cancel(struct dialer *d, struct ev_loop *loop);

int dialer_get(struct dialer *d);

#endif /* DIALER_H */
