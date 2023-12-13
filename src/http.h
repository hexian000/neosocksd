/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_H
#define HTTP_H

#include "server.h"
#include "util.h"

#include <stddef.h>

struct dialreq;

/* http_proxy_serve: implements serve_fn */
void http_proxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

/* http_api_serve: implements serve_fn */
void http_api_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* HTTP_H */
