#ifndef DIALER_H
#define DIALER_H

#include "conf.h"
#include "resolver.h"
#include "sockutil.h"
#include "util.h"
#include "utils/buffer.h"

#include <ev.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum proxy_protocol {
	PROTO_SOCKS4A = 4,
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
	char *addr;
	size_t addrlen;
};

struct dialreq {
	struct dialaddr addr;
	size_t num_proxy;
	struct proxy_req proxy[];
};

struct dialreq *dialreq_new(const struct dialaddr *addr, size_t num_proxy);
bool dialreq_proxy(
	struct dialreq *r, enum proxy_protocol protocol, const char *addr,
	size_t addrlen);
void dialreq_free(struct dialreq *r);

struct sockaddr;

#define DIALER_BUF_SIZE 1024

struct dialer {
	struct resolver resolver;
	const struct config *conf;
	struct event_cb done_cb;
	struct dialreq *req;
	size_t jump;
	int state;
	int fd, err;
	struct ev_io watcher;
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

#endif /* DIALER_H */
