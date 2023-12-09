/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_IMPL_H
#define HTTP_IMPL_H

#include "http.h"
#include "net/http.h"
#include "session.h"
#include "utils/buffer.h"
#include "utils/slog.h"
#include "utils/debug.h"
#include "transfer.h"
#include "dialer.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#define HTTP_MAX_ENTITY 8192
#define HTTP_MAX_CONTENT 4194304

struct http_ctx;

typedef void (*http_handler_fn)(struct ev_loop *loop, struct http_ctx *ctx);

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_HEADER,
	STATE_CONTENT,
	STATE_HANDLE,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

enum content_encodings {
	CENCODING_NONE,
	CENCODING_DEFLATE,
	CENCODING_GZIP,
};

struct httpreq {
	struct http_message msg;
	char *nxt;
	size_t content_length;
	const char *content_type;
	enum content_encodings content_encoding;
	enum content_encodings accept_encoding;
	bool expect_continue : 1;
};

struct http_ctx {
	struct session ss;
	struct server *s;
	enum http_state state;
	http_handler_fn handle;
	int accepted_fd, dialed_fd;
	sockaddr_max_t accepted_sa;
	struct ev_timer w_timeout;
	union {
		struct {
			struct ev_io w_recv, w_send;
			struct httpreq http;
			struct dialreq *dialreq;
			struct dialer dialer;
			size_t wpos, cpos;
			struct vbuffer *cbuf; /* content buffer */
			struct {
				BUFFER_HDR;
				unsigned char data[HTTP_MAX_ENTITY];
			} rbuf, wbuf;
		};
		struct { /* connected */
			struct transfer uplink, downlink;
		};
	};
};

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
		      (ctx)->http.msg.req.url, __VA_ARGS__);                   \
	} while (0)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

#define RESPHDR_BEGIN(buf, code)                                               \
	do {                                                                   \
		char date_str[32];                                             \
		const size_t date_len = http_date(date_str, sizeof(date_str)); \
		const char *status = http_status((code));                      \
		(buf).len = 0;                                                 \
		BUF_APPENDF(                                                   \
			(buf),                                                 \
			"HTTP/1.1 %" PRIu16 " %s\r\n"                          \
			"Date: %.*s\r\n"                                       \
			"Connection: close\r\n",                               \
			(code), status ? status : "", (int)date_len,           \
			date_str);                                             \
	} while (0)

#define RESPHDR_ADD(buf, format, ...) BUF_APPENDF((buf), (format), __VA_ARGS__)

#define RESPHDR_FINISH(buf) BUF_APPENDCONST(buf, "\r\n")

void http_resp_errpage(struct http_ctx *ctx, uint16_t code);

void http_handle_proxy(struct ev_loop *loop, struct http_ctx *ctx);
void http_handle_api(struct ev_loop *loop, struct http_ctx *ctx);

#endif /* HTTP_IMPL_H */
