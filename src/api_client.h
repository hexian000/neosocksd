/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef API_CLIENT_H
#define API_CLIENT_H

#include "util.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct dialreq;

struct api_client_cb {
	void (*func)(
		handle_type h, struct ev_loop *loop, void *ctx, bool ok,
		const void *data, size_t len);
	void *ctx;
};

handle_type api_invoke(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *content, size_t len, struct api_client_cb cb);

void api_cancel(struct ev_loop *loop, handle_type h);

#endif /* API_CLIENT_H */
