/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKS_H
#define SOCKS_H

#include "server.h"

/* socks_serve: implements serve_fn */
void socks_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* SOCKS_H */
