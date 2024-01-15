/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "http_parser.h"
#include "dialer.h"
#include "session.h"
#include "transfer.h"

#include "net/http.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/object.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

struct http_ctx;

typedef void (*http_handler_fn)(struct ev_loop *loop, struct http_ctx *ctx);

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct http_ctx {
	struct session ss;
	struct server *s;
	enum http_state state;
	http_handler_fn handle;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct ev_timer w_timeout;
	union {
		struct {
			struct ev_io w_recv, w_send;
			struct dialreq *dialreq;
			struct dialer dialer;
			struct http_parser parser;
		};
		struct { /* connected */
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct session, struct http_ctx, ss);

void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *ctx);
void http_ctx_close(struct ev_loop *loop, struct http_ctx *ctx);

#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char laddr[64];                                                \
		format_sa(&(ctx)->accepted_sa.sa, laddr, sizeof(laddr));       \
		if ((ctx)->state != STATE_CONNECT) {                           \
			LOG_F(level, "\"%s\": " format, laddr, __VA_ARGS__);   \
			break;                                                 \
		}                                                              \
		LOG_F(level, "\"%s\" -> \"%s\": " format, laddr,               \
		      (ctx)->parser.msg.req.url, __VA_ARGS__);                 \
	} while (0)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

void http_handle_proxy(struct ev_loop *loop, struct http_ctx *ctx);
void http_handle_api(struct ev_loop *loop, struct http_ctx *ctx);

#endif /* HTTP_SERVER_H */
