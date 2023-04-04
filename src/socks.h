/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKS_H
#define SOCKS_H

#include "server.h"
#include "stats.h"

#include <ev.h>

#include <stddef.h>

/* socks_serve: implements serve_fn */
void socks_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

void socks_read_stats(struct stats *out_stats);

#endif /* SOCKS_H */
