/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

struct server;
struct ev_loop;
struct sockaddr;

/* http_proxy_serve: implements serve_fn */
void http_proxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* HTTP_PROXY_H */
