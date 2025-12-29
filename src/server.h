/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct listener_stats {
	uintmax_t num_accept;
	uintmax_t num_serve;
};

/* The listener binds to an address and accepts incoming connections */
struct listener {
	ev_io w_accept;
	ev_timer w_timer;
	struct listener_stats stats;
};

struct server_stats {
	size_t num_halfopen; /**< Number of half-open connections */
	size_t num_sessions; /**< Number of active sessions */
	uintmax_t num_request; /**< Total number of requests processed */
	uintmax_t num_success; /**< Number of successful requests */
	uintmax_t byt_up; /**< Bytes uploaded */
	uintmax_t byt_down; /**< Bytes downloaded */
	int_least64_t started; /**< Server start timestamp */
};

struct sockaddr;
struct server;

/**
 * @brief Function pointer type for serving connections
 *
 * @param s The server instance
 * @param loop The event loop
 * @param accepted_fd File descriptor of the accepted connection
 * @param accepted_sa Peer address of the accepted connection
 */
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
