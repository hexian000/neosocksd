/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef FORWARD_H
#define FORWARD_H

#include "server.h"

/* forward_serve: implements serve_fn */
void forward_serve(
	struct server *restrict s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* FORWARD_H */
