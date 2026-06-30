/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file http.h
 * @brief HTTP parsing and utility functions
 */

#ifndef PROTO_HTTP_H
#define PROTO_HTTP_H

#include "net/http.h"
#include "utils/buffer.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum size for HTTP entity headers */
#define HTTP_MAX_ENTITY 8192
/** Maximum size for HTTP content body */
#define HTTP_MAX_CONTENT 4194304

/** Transfer encoding types supported by the HTTP parser */
enum transfer_encodings {
	TENCODING_NONE,
	TENCODING_CHUNKED,
};

/** Content encoding types supported by the HTTP parser */
enum content_encodings {
	CENCODING_NONE,
	CENCODING_DEFLATE,
	CENCODING_GZIP,
	CENCODING_MAX,
};

/** String representations of content encodings */
extern const char *http_content_encoding_str[];

/** @brief Parsed HTTP headers structure */
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
		char *host;
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

/** HTTP connection state machine states */
enum http_conn_state {
	STATE_PARSE_REQUEST,
	STATE_PARSE_RESPONSE,
	STATE_PARSE_HEADER,
	STATE_PARSE_CONTENT,
	STATE_PARSE_ERROR,
	STATE_PARSE_OK,
};

/** @brief Callback for custom header processing during parsing */
struct http_parsehdr_cb {
	bool (*func)(void *ctx, const char *key, char *value);
	void *ctx;
};

enum http_body_mode {
	HTTP_BODY_NONE,
	HTTP_BODY_CONTENT_LENGTH,
	HTTP_BODY_CHUNKED,
	HTTP_BODY_EOF,
};

enum http_body_chunk_state {
	HTTP_BODY_CHUNK_SIZE_LINE,
	HTTP_BODY_CHUNK_DATA,
	HTTP_BODY_CHUNK_DATA_CR,
	HTTP_BODY_CHUNK_DATA_LF,
	HTTP_BODY_CHUNK_TRAILER_LINE,
	HTTP_BODY_CHUNK_DONE,
};

struct http_body {
	enum http_body_mode mode;
	size_t content_length;
	size_t consumed;
	size_t chunk_left;
	size_t line_len;
	char line[128];
	enum http_body_chunk_state chunk_state;
	bool done : 1;
};

struct http_body_data_cb {
	bool (*func)(void *ctx, const unsigned char *data, size_t len);
	void *ctx;
};

/** @brief HTTP connection state and I/O buffers for streaming message parsing */
struct http_conn {
	enum http_conn_state state;
	/* initial state, distinguishes request/response parsing */
	enum http_conn_state mode;
	int http_status;
	int fd;
	uint_least64_t *byt_recv, *byt_sent;
	struct http_message msg;
	char *next;
	bool expect_continue : 1;
	struct http_headers hdr;
	struct http_parsehdr_cb on_header;
	size_t wpos, cpos;
	/* content buffer */
	struct vbuffer *cbuf;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_ENTITY];
	} rbuf, wbuf;
};

/**
 * @brief Initialize HTTP connection.
 * @param p Connection instance
 * @param fd Socket file descriptor
 * @param mode Initial parse state (request or response)
 * @param on_header Header processing callback
 */
void http_conn_init(
	struct http_conn *restrict p, const int fd,
	const enum http_conn_state mode,
	const struct http_parsehdr_cb on_header, uint_least64_t *const byt_recv,
	uint_least64_t *const byt_sent);

/**
 * @brief Receive and parse HTTP data.
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_conn_recv(struct http_conn *restrict p);

/**
 * @brief Send pending HTTP data (header buffer first, then content buffer).
 * @param p Connection instance
 * @param fd Socket file descriptor
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_conn_send(struct http_conn *restrict p, const int fd);

void http_body_init(
	struct http_body *restrict d, const enum http_body_mode mode,
	const size_t content_length);

bool http_body_consume(
	struct http_body *restrict d, const unsigned char *restrict data,
	const size_t len, const struct http_body_data_cb on_data);

bool http_body_finish(struct http_body *restrict d);

/**
 * @brief Parse Accept-TE header. Currently detects chunked encoding.
 * @param p Parser instance
 * @param value Header value
 * @return true on success
 */
bool parsehdr_accept_te(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Parse Transfer-Encoding header. Currently detects chunked.
 * @param p Parser instance
 * @param value Header value
 * @return true on success
 */
bool parsehdr_transfer_encoding(
	struct http_conn *restrict p, char *restrict value);

/**
 * @brief Parse Accept-Encoding header; ignores quality values.
 *
 * Currently supports deflate.
 *
 * @param p Parser instance
 * @param value Header value
 * @return true if at least one supported encoding found
 */
bool parsehdr_accept_encoding(
	struct http_conn *restrict p, char *restrict value);

/**
 * @brief Parse Content-Length header. CONNECT requests must not carry one.
 * @param p Parser instance
 * @param value Header value
 * @return true if parsed and valid
 */
bool parsehdr_content_length(
	struct http_conn *restrict p, const char *restrict value);

/**
 * @brief Parse Content-Encoding header; sets error status if unsupported.
 * @param p Parser instance
 * @param value Header value
 * @return true if encoding is supported
 */
bool parsehdr_content_encoding(
	struct http_conn *restrict p, const char *restrict value);

/**
 * @brief Parse Expect header. Only "100-continue" is supported;
 *        sets error status for any other expectation.
 * @param p Parser instance
 * @param value Header value
 * @return true if expectation is supported
 */
bool parsehdr_expect(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Record Connection header value for hop-by-hop token lookup.
 * @return true always
 */
bool parsehdr_connection(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Iterate over comma-separated tokens in a Connection header value.
 *
 * Models the same iterator pattern as http_parsehdr(): the caller passes
 * the current position and receives the next one on each call.  Skips OWS
 * and comma separators between tokens per RFC 7230 token-list ABNF.
 *
 * @param p  Current parse position; NULL is accepted and causes immediate
 *           termination.
 * @param tok  Set to the start of the next token, or NULL when no tokens
 *             remain.  The pointed-to memory is within the original string.
 * @param toklen  Set to the byte length of the token.
 * @return  New parse position to pass on the next call.
 */
const char *parsehdr_connection_token(
	const char *restrict p, const char **restrict tok,
	size_t *restrict toklen);

/** @brief Write an HTTP error response page into @p p's write buffer. */
void http_resp_errpage(struct http_conn *restrict p, const uint_fast16_t code);

/**
 * @brief Create a decompressing stream reader over a content buffer.
 * @param buf Content buffer to read from
 * @param len Length of content buffer
 * @param encoding Content encoding type
 * @return Stream for reading decoded content, or NULL on error
 */
struct stream *content_reader(
	const void *restrict buf, const size_t len,
	const enum content_encodings encoding);

/**
 * @brief Create a compressing stream writer into a vbuffer.
 *
 * @p *pvbuf may be reallocated as output grows.
 *
 * @param pvbuf Pointer to vbuffer pointer (may be reallocated)
 * @param bufsize Initial buffer size
 * @param encoding Content encoding type
 * @return Stream for writing encoded content
 */
struct stream *content_writer(
	struct vbuffer **restrict pvbuf, const size_t bufsize,
	const enum content_encodings encoding);

/**
 * @brief Begin HTTP response header (status line + Date header).
 * @param buf Buffer to write response headers
 * @param code HTTP status code
 */
#define RESPHDR_BEGIN(buf, code)                                               \
	do {                                                                   \
		char date_str[32];                                             \
		const size_t date_len = http_date(date_str, sizeof(date_str)); \
		const char *status = http_status((code));                      \
		(buf).len = 0;                                                 \
		BUF_APPENDF(                                                   \
			(buf),                                                 \
			"HTTP/1.1 %" PRIuFAST16 " %s\r\n"                      \
			"Date: %.*s\r\n",                                      \
			(uint_fast16_t)(code), status ? status : "",           \
			(int)date_len, date_str);                              \
	} while (0)

/** @brief Add plain text content type headers */
#define RESPHDR_CPLAINTEXT(buf)                                                \
	BUF_APPENDSTR(                                                         \
		(buf), "Content-Type: text/plain; charset=utf-8\r\n"           \
		       "X-Content-Type-Options: nosniff\r\n")

/** @brief Add Content-Type header */
#define RESPHDR_CTYPE(buf, type)                                               \
	BUF_APPENDF((buf), "Content-Type: %s\r\n", (type))

/** @brief Add Content-Length header */
#define RESPHDR_CLENGTH(buf, len)                                              \
	BUF_APPENDF((buf), "Content-Length: %zu\r\n", (len))

/** @brief Add Content-Encoding header */
#define RESPHDR_CENCODING(buf, encoding)                                       \
	BUF_APPENDF((buf), "Content-Encoding: %s\r\n", (encoding))

/** @brief Add no-cache headers */
#define RESPHDR_NOCACHE(buf) BUF_APPENDSTR((buf), "Cache-Control: no-store\r\n")

/** @brief Add Connection: close header */
#define RESPHDR_CONN_CLOSE(buf) BUF_APPENDSTR((buf), "Connection: close\r\n")

/** @brief Add Connection: keep-alive header */
#define RESPHDR_CONN_KEEPALIVE(buf)                                            \
	BUF_APPENDSTR((buf), "Connection: keep-alive\r\n")

/** @brief Finish HTTP response headers */
#define RESPHDR_FINISH(buf) BUF_APPENDSTR(buf, "\r\n")

#if WITH_RULESET
/** RPC call MIME type components */
#define MIME_RPCALL_TYPE "application"
#define MIME_RPCALL_SUBTYPE "x-neosocksd-rpc"
#define MIME_RPCALL_VERSION "1"

/** Complete RPC call MIME type string */
#define MIME_RPCALL                                                            \
	MIME_RPCALL_TYPE "/" MIME_RPCALL_SUBTYPE                               \
			 "; version=" MIME_RPCALL_VERSION

/** @brief Return true if @p mime_type matches the RPC call MIME type. */
bool check_rpcall_mime(char *restrict mime_type);

/** Minimum size threshold for RPC call compression */
#define RPCALL_COMPRESS_THRESHOLD 256
#endif /* WITH_RULESET */

#endif /* PROTO_HTTP_H */
