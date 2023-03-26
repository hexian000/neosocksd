/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef FORWARD_H
#define FORWARD_H

#include "server.h"
#include "sockutil.h"

#include <ev.h>

/* forward_serve: implements serve_fn */
void forward_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

size_t forward_get_halfopen(void);

#endif /* FORWARD_H */
