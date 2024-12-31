/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef FORWARD_H
#define FORWARD_H

struct server;
struct ev_loop;
struct sockaddr;

/* forward_serve: implements serve_fn */
void forward_serve(
	struct server *restrict s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#if WITH_TPROXY
/* tproxy_serve: implements serve_fn */
void tproxy_serve(
	struct server *restrict s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);
#endif

#endif /* FORWARD_H */
