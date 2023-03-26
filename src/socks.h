/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKS_H
#define SOCKS_H

#include "server.h"

#include <ev.h>

#include <stddef.h>

/* socks_serve: implements serve_fn */
void socks_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

size_t socks_get_halfopen(void);

#endif /* SOCKS_H */
