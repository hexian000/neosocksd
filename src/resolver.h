#ifndef RESOLVER_H
#define RESOLVER_H

#include "sockutil.h"

#include <stdbool.h>

struct ev_loop;
struct resolve_ctx;

void resolver_init(void);
void resolver_uninit(void);

bool resolver_set_server(const char *nameserver);

typedef void (*resolver_cb)(
	struct ev_loop *loop, const struct sockaddr *sa, void *data);

void resolver_do(
	struct ev_loop *loop, const char *host, int family, const resolver_cb cb,
	void *data);

#endif /* RESOLVER_H */
