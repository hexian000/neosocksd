#ifndef DIALER_H
#define DIALER_H

#include "conf.h"
#include "proto/socks.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "net/url.h"
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

enum dialer_error {
	DIALER_SUCCESS,
	DIALER_SYSERR,
	DIALER_TIMEOUT,
	DIALER_PROXYERR,
};

struct dialer {
	const struct config *conf;
	struct event_cb done_cb;
	struct dialreq *req;
	size_t jump;
	int state;
	enum dialer_error err;
	int fd, syserr;
	struct ev_io w_socket;
	struct ev_timer w_timeout;
	struct {
		BUFFER_HDR;
		unsigned char data[DIALER_BUF_SIZE];
	} buf;
};

void dialer_init(
	struct dialer *d, const struct config *conf, const struct event_cb *cb);

bool dialer_start(struct dialer *d, struct ev_loop *loop, struct dialreq *req);

void dialer_stop(struct dialer *d, struct ev_loop *loop);

int dialer_get(struct dialer *d);

const char *dialer_strerror(struct dialer *d);

#endif /* DIALER_H */
