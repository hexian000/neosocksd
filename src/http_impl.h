#ifndef HTTP_IMPL_H
#define HTTP_IMPL_H

#include "http.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "transfer.h"
#include "dialer.h"

#include <ev.h>

#include <inttypes.h>

#define HTTP_MAX_HEADER_COUNT 256
#define HTTP_MAX_ENTITY 8192

struct http_ctx;

typedef void (*http_handler_fn)(struct ev_loop *loop, struct http_ctx *ctx);

struct http_hdr_item {
	const char *key, *value;
};

enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_HEADER,
	STATE_CONTENT,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct http_ctx {
	struct server *s;
	enum http_state state;
	http_handler_fn handle;
	int accepted_fd, dialed_fd;
	sockaddr_max_t accepted_sa;
	struct ev_timer w_timeout;
	union {
		struct {
			struct ev_io w_recv, w_send;
			struct http_message http_msg;
			char *http_nxt;
			struct http_hdr_item http_hdr[HTTP_MAX_HEADER_COUNT];
			size_t http_hdr_num, content_length;
			unsigned char *content;
			struct dialer dialer;
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
		LOG_F(level, "\"%s\": " format, laddr, __VA_ARGS__);           \
	} while (0)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

#define RESPHDR_WRITE(buf, code, hdr)                                          \
	do {                                                                   \
		char date_str[32];                                             \
		const size_t date_len = http_date(date_str, sizeof(date_str)); \
		const char *status = http_status((code));                      \
		(buf).len = 0;                                                 \
		BUF_APPENDF(                                                   \
			buf,                                                   \
			"HTTP/1.1 %" PRIu16 " %s\r\n"                          \
			"Date: %.*s\r\n"                                       \
			"Connection: close\r\n"                                \
			"%s\r\n",                                              \
			code, status ? status : "", (int)date_len, date_str,   \
			(hdr));                                                \
	} while (0)

#define RESPHDR_CODE(buf, code) RESPHDR_WRITE((buf), (code), "")

#define RESPHDR_POST(buf, code)                                                \
	RESPHDR_WRITE(                                                         \
		(buf), (code),                                                 \
		"Content-Type: text/plain; charset=utf-8\r\n"                  \
		"X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_GET(buf, code)                                                 \
	RESPHDR_WRITE(                                                         \
		(buf), (code),                                                 \
		"Content-Type: text/plain; charset=utf-8\r\n"                  \
		"X-Content-Type-Options: nosniff\r\n"                          \
		"Cache-Control: no-store\r\n")

void http_resp_errpage(struct http_ctx *ctx, uint16_t code);

void http_handle_proxy(struct ev_loop *loop, struct http_ctx *ctx);
void http_handle_api(struct ev_loop *loop, struct http_ctx *ctx);

#endif /* HTTP_IMPL_H */
