/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include <ev.h>

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct listener_stats {
	uintmax_t num_accept;
	uintmax_t num_serve;
};

/* the listener binds to an address and accepts incoming connections */
struct listener {
	struct ev_io w_accept;
	struct ev_timer w_timer;
	struct listener_stats stats;
};

struct server_stats {
	size_t num_halfopen;
	size_t num_sessions;
	uintmax_t num_request;
	uintmax_t num_success;
	uintmax_t byt_up, byt_down;
	ev_tstamp started;
};

struct sockaddr;
struct server;

typedef void (*serve_fn)(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa);

struct server {
	struct ev_loop *loop;
	struct listener l;
	struct server_stats stats;
	void *data;

	serve_fn serve;
};

void server_init(
	struct server *s, struct ev_loop *loop, serve_fn serve, void *data);

bool server_start(struct server *s, const struct sockaddr *bindaddr);

void server_stop(struct server *s);

#endif /* SERVER_H */
