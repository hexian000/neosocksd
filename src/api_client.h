/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef API_CLIENT_H
#define API_CLIENT_H

#include <stddef.h>

struct ev_loop;
struct dialreq;
struct api_client_ctx;
struct stream;

struct api_client_cb {
	void (*func)(
		struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
		const char *errmsg, size_t errlen, struct stream *stream);
	void *data;
};

void api_client_invoke(
	struct ev_loop *loop, struct dialreq *req, const char *payload,
	size_t len);

struct api_client_ctx *api_client_rpcall(
	struct ev_loop *loop, struct dialreq *req, const char *payload,
	size_t len, const struct api_client_cb *cb);

void api_client_cancel(struct ev_loop *loop, struct api_client_ctx *ctx);

#endif /* API_CLIENT_H */
