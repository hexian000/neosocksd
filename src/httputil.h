/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "net/http.h"
#include "utils/buffer.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HTTP_MAX_ENTITY 8192
#define HTTP_MAX_CONTENT 4194304

enum transfer_encodings {
	TENCODING_NONE,
	TENCODING_CHUNKED,
};

enum content_encodings {
	CENCODING_NONE,
	CENCODING_DEFLATE,
	CENCODING_GZIP,
	CENCODING_MAX,
};

extern const char *content_encoding_str[];

struct http_headers {
	/* hop-by-hop headers */
	char *connection;
	struct {
		enum transfer_encodings accept;
		enum transfer_encodings encoding;
	} transfer;
	/* representation headers */
	struct {
		bool has_length : 1;
		size_t length;
		char *type;
		enum content_encodings encoding;
	} content;
	/* request headers */
	struct {
		enum content_encodings accept_encoding;
		struct {
			char *type;
			char *credentials;
		} authorization;
		struct {
			char *type;
			char *credentials;
		} proxy_authorization;
	};
};

enum http_parser_state {
	STATE_PARSE_REQUEST,
	STATE_PARSE_RESPONSE,
	STATE_PARSE_HEADER,
	STATE_PARSE_CONTENT,
	STATE_PARSE_ERROR,
	STATE_PARSE_OK,
};

struct http_parsehdr_cb {
	bool (*func)(void *ctx, const char *key, char *value);
	void *ctx;
};

struct http_parser {
	enum http_parser_state state;
	int http_status;
	int fd;
	struct http_message msg;
	char *next;
	bool expect_continue : 1;
	struct http_headers hdr;
	struct http_parsehdr_cb on_header;
	size_t wpos, cpos;
	struct vbuffer *cbuf; /* content buffer */
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_ENTITY];
	} rbuf, wbuf;
};

void http_parser_init(
	struct http_parser *p, int fd, enum http_parser_state mode,
	struct http_parsehdr_cb on_header);

int http_parser_recv(struct http_parser *parser);

bool parsehdr_accept_te(struct http_parser *restrict p, char *value);
bool parsehdr_transfer_encoding(struct http_parser *restrict p, char *value);
bool parsehdr_accept_encoding(struct http_parser *restrict p, char *value);
bool parsehdr_content_length(struct http_parser *restrict p, char *value);
bool parsehdr_content_encoding(struct http_parser *restrict p, char *value);
bool parsehdr_expect(struct http_parser *restrict p, char *value);

void http_resp_errpage(struct http_parser *parser, uint16_t code);

bool http_resp_established(struct http_parser *parser);

struct stream *
content_reader(const void *buf, size_t len, enum content_encodings encoding);

struct stream *content_writer(
	struct vbuffer **pvbuf, size_t bufsize,
	enum content_encodings encoding);

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

#define RESPHDR_CPLAINTEXT(buf)                                                \
	BUF_APPENDSTR(                                                         \
		(buf), "Content-Type: text/plain; charset=utf-8\r\n"           \
		       "X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_CTYPE(buf, type)                                               \
	BUF_APPENDF((buf), "Content-Type: %s\r\n", (type))

#define RESPHDR_CLENGTH(buf, len)                                              \
	BUF_APPENDF((buf), "Content-Length: %zu\r\n", (len))

#define RESPHDR_CENCODING(buf, encoding)                                       \
	BUF_APPENDF((buf), "Content-Encoding: %s\r\n", (encoding))

#define RESPHDR_NOCACHE(buf) BUF_APPENDSTR((buf), "Cache-Control: no-store\r\n")

#define RESPHDR_FINISH(buf) BUF_APPENDSTR(buf, "\r\n")

#if WITH_RULESET
#define MIME_RPCALL_TYPE "application"
#define MIME_RPCALL_SUBTYPE "x-neosocksd-rpc"
#define MIME_RPCALL_VERSION "1"

#define MIME_RPCALL                                                            \
	MIME_RPCALL_TYPE "/" MIME_RPCALL_SUBTYPE                               \
			 "; version=" MIME_RPCALL_VERSION

bool check_rpcall_mime(char *mime_type);
#endif /* WITH_RULESET */

#endif /* HTTP_PARSER_H */
