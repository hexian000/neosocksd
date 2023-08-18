#ifndef DIALER_H
#define DIALER_H

#include "proto/socks.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "resolver.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum proxy_protocol {
	PROTO_HTTP,
	PROTO_SOCKS4A,
	PROTO_SOCKS5,
};

enum dialaddr_type {
	ATYP_INET,
	ATYP_INET6,
	ATYP_DOMAIN,
};

struct dialaddr {
	enum dialaddr_type type;
	union {
		struct in_addr in;
		struct in6_addr in6;
		struct domain_name domain;
	};
	uint16_t port;
};

bool dialaddr_set(struct dialaddr *addr, const char *s, size_t len);
int dialaddr_format(const struct dialaddr *addr, char *buf, size_t bufsize);

struct proxy_req {
	enum proxy_protocol proto;
	struct dialaddr addr;
};

struct dialreq {
	struct dialaddr addr;
	size_t num_proxy;
	struct proxy_req proxy[];
};

struct dialreq *dialreq_new(const struct dialaddr *addr, size_t num_proxy);
bool dialreq_proxy(struct dialreq *r, const char *addr, size_t addrlen);
void dialreq_free(struct dialreq *r);

struct sockaddr;

#define DIALER_BUF_SIZE                                                        \
	MAX(sizeof("CONNECT") + (FQDN_MAX_LENGTH + sizeof(":65535")) +         \
		    sizeof("HTTP/1.1\r\n"),                                    \
	    SOCKS_MAX_LENGTH)

struct dialer {
	struct event_cb done_cb;
	const struct dialreq *req;
	struct resolve_query resolve_query;
	size_t jump;
	int state;
	int fd, syserr;
	struct ev_io w_socket;
	struct {
		BUFFER_HDR;
		unsigned char data[DIALER_BUF_SIZE];
	} buf;
};

void dialer_init(struct dialer *d, const struct event_cb cb);

void dialer_start(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req);

void dialer_cancel(struct dialer *d, struct ev_loop *loop);

int dialer_get(struct dialer *d);

#endif /* DIALER_H */
