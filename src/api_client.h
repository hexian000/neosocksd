/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef API_CLIENT_H
#define API_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct config;
struct dialreq;
struct resolver;
struct server_stats;
struct api_client_ctx;
struct io_stream;

/* The completion callback for api_client_rpcall. The ctx handle passed to
 * api_client_rpcall's *pctx is valid only until this callback is invoked: the
 * request is torn down as soon as the callback returns, so the callback must
 * not retain the handle or call api_client_cancel() on it (cancel is a bare
 * gc_unref that, combined with the completion teardown, would double-free the
 * ctx). Cancel only a request whose callback has not yet fired. */
struct api_client_cb {
	void (*func)(
		struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
		const char *errmsg, size_t errlen, struct io_stream *stream);
	void *data;
};

/* Collaborators an API request runs against; they all come from the same
 * ruleset. A NULL stats leaves the request uncounted. Not retained -- the
 * request copies what it needs. */
struct api_client_opts {
	const struct config *conf;
	struct resolver *resolver;
	struct server_stats *stats;
};

void api_client_invoke(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const void *restrict payload, size_t len,
	const struct api_client_opts *restrict opts);

bool api_client_rpcall(
	struct ev_loop *restrict loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const void *restrict payload, size_t len,
	const struct api_client_cb *restrict cb,
	const struct api_client_opts *restrict opts);

void api_client_cancel(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx);

#endif /* API_CLIENT_H */
