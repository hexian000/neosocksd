/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef API_CLIENT_H
#define API_CLIENT_H

#include "util.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct dialreq;
struct api_client_ctx;

struct api_client_cb {
	void (*func)(
		struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
		bool ok, const void *payload, size_t len);
	void *data;
};

struct api_client_ctx *api_invoke(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *payload, size_t len, struct api_client_cb cb);

void api_cancel(struct ev_loop *loop, struct api_client_ctx *ctx);

#endif /* API_CLIENT_H */
