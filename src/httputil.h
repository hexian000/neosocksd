/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "util.h"

#include "net/http.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
		char *accept;
		enum content_encodings accept_encoding;
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

static inline char *strtrimleftspace(char *restrict s)
{
	for (; *s && isspace((unsigned char)*s); s++) {
	}
	return s;
}

static inline char *strtrimrightspace(char *restrict s)
{
	char *restrict e = s + strlen(s) - 1;
	for (; s < e && isspace((unsigned char)*e); e--) {
		*e = '\0';
	}
	return s;
}

static inline char *strtrimspace(char *s)
{
	return strtrimrightspace(strtrimleftspace(s));
}

static inline char *strlower(char *s)
{
	for (char *p = s; *p != '\0'; ++p) {
		*s = (unsigned char)tolower((unsigned char)*s);
	}
	return s;
}

static inline bool
parsehdr_accept_te(struct http_parser *restrict p, char *value)
{
	value = strtrimspace(value);
	if (value[0] == '\0') {
		p->hdr.transfer.accept = TENCODING_NONE;
		return true;
	}
	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.accept = TENCODING_CHUNKED;
		return true;
	}
	return false;
}

static inline bool
parsehdr_transfer_encoding(struct http_parser *restrict p, char *value)
{
	value = strtrimspace(value);
	if (value[0] == '\0') {
		p->hdr.transfer.encoding = TENCODING_NONE;
		return true;
	}
	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.encoding = TENCODING_CHUNKED;
		return true;
	}
	return false;
}

static inline bool
parsehdr_accept_encoding(struct http_parser *restrict p, char *value)
{
	if (strcmp(value, "*") == 0) {
		p->hdr.accept_encoding = CENCODING_DEFLATE;
		return true;
	}
	const char *deflate = content_encoding_str[CENCODING_DEFLATE];
	for (char *token = strtok(value, ","); token != NULL;
	     token = strtok(NULL, ",")) {
		char *q = strchr(token, ';');
		if (q != NULL) {
			*q = '\0';
		}
		token = strtrimspace(token);
		if (strcasecmp(token, deflate) == 0) {
			p->hdr.accept_encoding = CENCODING_DEFLATE;
			return true;
		}
	}
	return false;
}

static inline bool
parsehdr_content_length(struct http_parser *restrict p, char *value)
{
	char *endptr;
	const uintmax_t lenvalue = strtoumax(value, &endptr, 10);
	if (*endptr || lenvalue > SIZE_MAX) {
		return false;
	}
	const size_t content_length = (size_t)lenvalue;
	if (strcmp(p->msg.req.method, "CONNECT") == 0) {
		return false;
	}
	p->hdr.content.has_length = true;
	p->hdr.content.length = content_length;
	return true;
}

static inline bool
parsehdr_content_encoding(struct http_parser *restrict p, char *value)
{
	for (size_t i = 0; i < CENCODING_MAX; i++) {
		if (content_encoding_str[i] == NULL) {
			continue;
		}
		if (strcasecmp(value, content_encoding_str[i]) == 0) {
			p->hdr.content.encoding = (enum content_encodings)i;
			return true;
		}
	}
	p->http_status = HTTP_UNSUPPORTED_MEDIA_TYPE;
	return false;
}

void http_resp_errpage(struct http_parser *parser, uint16_t code);

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
	BUF_APPENDCONST(                                                       \
		(buf), "Content-Type: text/plain; charset=utf-8\r\n"           \
		       "X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_CTYPE(buf, type)                                               \
	BUF_APPENDF((buf), "Content-Type: %s\r\n", (type))

#define RESPHDR_CLENGTH(buf, len)                                              \
	BUF_APPENDF((buf), "Content-Length: %zu\r\n", (len))

#define RESPHDR_CENCODING(buf, encoding)                                       \
	BUF_APPENDF((buf), "Content-Encoding: %s\r\n", (encoding))

#define RESPHDR_NOCACHE(buf)                                                   \
	BUF_APPENDCONST((buf), "Cache-Control: no-store\r\n")

#define RESPHDR_FINISH(buf) BUF_APPENDCONST(buf, "\r\n")

#if WITH_RULESET
#define MIME_RPCALL_TYPE "application"
#define MIME_RPCALL_SUBTYPE "x-neosocksd-rpc"
#define MIME_RPCALL_VERSION "1"

#define MIME_RPCALL                                                            \
	MIME_RPCALL_TYPE "/" MIME_RPCALL_SUBTYPE                               \
			 "; version=" MIME_RPCALL_VERSION

bool check_rpcall_mime(char *mime_type);

#define RPCALL_COMPRESS_THRESHOLD 262144
#endif /* WITH_RULESET */

#endif /* HTTP_PARSER_H */
