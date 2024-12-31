/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef API_SERVER_H
#define API_SERVER_H

struct server;
struct ev_loop;
struct sockaddr;

/* api_serve: implements serve_fn */
void api_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

#endif /* API_SERVER_H */
