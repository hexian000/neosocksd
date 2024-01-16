/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "util.h"

struct ev_loop;
struct dialreq;

struct http_client_cb {
	void (*func)(
		handle_type h, struct ev_loop *loop, void *ctx, bool ok,
		const void *data, size_t len);
	void *ctx;
};

handle_type http_client_do(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *content, size_t len, struct http_client_cb cb);

void http_client_cancel(struct ev_loop *loop, handle_type h);

#endif /* HTTP_CLIENT_H */
