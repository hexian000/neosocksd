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
#include <string.h>

/** Maximum size for HTTP entity headers */
#define HTTP_MAX_ENTITY 8192
/** Maximum combined length of repeated Connection field lines */
#define HTTP_MAX_CONNECTION 512
/** Maximum size for HTTP content body */
#define HTTP_MAX_CONTENT 4194304

/**
 * @brief Check that a start-line's HTTP-version names HTTP/1.x.
 * @details RFC 9112 §2.3: HTTP-version = HTTP-name "/" DIGIT "." DIGIT, so the
 *     field is exactly "HTTP/1." and one minor-version digit, nothing more.
 * @param version The HTTP-version field of a request-line or status-line
 * @return true if @p version is "HTTP/1." followed by a single DIGIT
 */
static inline bool http_version_is_1x(const char *restrict version)
{
	return strncmp(version, "HTTP/1.", 7) == 0 && '0' <= version[7] &&
	       version[7] <= '9' && version[8] == '\0';
}

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
extern const char *const http_content_encoding_str[];

/** @brief Parsed HTTP headers structure */
struct http_headers {
	/* hop-by-hop headers. RFC 9110 §5.3: repeated Connection field lines are
	 * one ordered token list; the first line is referenced in place and any
	 * further lines are comma-joined into `connection_store`, which
	 * `connection` then points at (never copied out of struct http_conn). */
	char *connection;
	char connection_store[HTTP_MAX_CONNECTION];
	size_t connection_stored;
	struct {
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
		bool has_host : 1;
		enum content_encodings accept_encoding;
		/* sticky `deflate;q=0` refusal, so a later Accept-Encoding line's
		 * `*` cannot re-select deflate across combined field lines */
		bool accept_deflate_refused : 1;
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
 * @brief Drive the parser over the bytes already in `rbuf`, reading nothing.
 *
 * For a caller that placed unparsed bytes in `rbuf` itself — carrying a
 * pipelined message across a keep-alive reset — where waiting for readability
 * would stall, the socket having already delivered them.
 *
 * On return, `rbuf` bytes before `next` are consumed (headers, and any
 * Content-Length body copied into `cbuf`); what follows is a later message.
 *
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_conn_parse(struct http_conn *restrict p);

/**
 * @brief Receive and parse HTTP data.
 *
 * Only a Content-Length delimited body is framed, into `cbuf`. A
 * `Transfer-Encoding: chunked` message parses to STATE_PARSE_OK with
 * `cbuf == NULL` and its body left unconsumed in `rbuf`; no caller accepts a
 * chunked body, so framing it here would be wasted work. Likewise a response
 * with neither Content-Length nor chunked, whose body runs to the connection
 * close (RFC 9112 6.3), parses to STATE_PARSE_OK as soon as its header block
 * ends, with `cbuf == NULL` and the body unread. (A request with neither has
 * no body, RFC 9112 6.3, so `cbuf == NULL` is its true, empty body.)
 *
 * A caller that consumes `cbuf` must therefore reject both itself, or it will
 * silently see an empty body. Both do: api_server's `restapi_check` answers
 * 501 for every chunked REST request, and api_client's `on_http_client_done`
 * reports an error for a chunked rpcall/invoke response and for a
 * close-delimited 2xx rpcall response. Check `hdr.transfer.encoding` and
 * `hdr.content.has_length` before relying on `cbuf`.
 *
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_conn_recv(struct http_conn *restrict p);

/**
 * @brief Send pending HTTP data (header buffer first, then content buffer).
 * @param p Connection instance
 * @param fd Socket file descriptor
 * @param[out] err Set to the socket_send() error code when -1 is returned
 * (0 otherwise); lets callers branch on the failure without reading errno.
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_conn_send(
	struct http_conn *restrict p, const int fd, int *restrict err);

/**
 * @brief Parse Transfer-Encoding header. Currently detects chunked.
 *
 * The value is a comma-separated transfer-coding list; empty list elements are
 * ignored. A list ending in chunked that also names a coding this parser does
 * not implement sets @c http_status to 501 Not Implemented (RFC 9112 §6.1);
 * every other rejection is a framing error and keeps the default 400.
 *
 * @param p Parser instance
 * @param value Header value, split in place
 * @return true on success; false for a list whose final coding is not chunked,
 *     for chunked applied more than once (within the list or across field
 *     lines), for an ambiguous Content-Length + chunked framing, or for an
 *     unimplemented coding before chunked
 */
bool parsehdr_transfer_encoding(
	struct http_conn *restrict p, char *restrict value);

/**
 * @brief Parse Accept-Encoding header; honors quality values.
 *
 * Currently supports deflate. RFC 9110 §12.5.3: a weight of q=0 refuses the
 * coding, and a refused deflate stays refused across the combined field value.
 *
 * @param p Parser instance
 * @param value Header value
 * @return always true; a value with no acceptable supported coding leaves
 *     @c accept_encoding at @c CENCODING_NONE, which the RFC's identity
 *     fallback makes a valid outcome rather than a rejected header
 */
bool parsehdr_accept_encoding(
	struct http_conn *restrict p, char *restrict value);

/**
 * @brief Validate a Content-Length field value and convert it to a size_t.
 *
 * RFC 9110 §8.6: Content-Length is 1*DIGIT with no sign, prefix, or trailing
 * garbage. Rejects a value that overflows @c uintmax_t (ERANGE) or exceeds
 * @c SIZE_MAX. Applies none of the RFC 9112 §6.3 framing rules (duplicate
 * header, Transfer-Encoding conflict, CONNECT) — the caller owns those.
 *
 * @param value Field value (trailing OWS is expected to be already stripped).
 * @param[out] out Receives the parsed length on success; untouched on failure.
 * @return true if @p value is a well-formed length that fits in @c size_t.
 */
bool http_parse_content_length(const char *restrict value, size_t *restrict out);

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

/** @brief Result of parsehdr_representation(). */
enum parsehdr_result {
	PARSEHDR_UNHANDLED, /**< key is not one of these headers */
	PARSEHDR_OK, /**< key handled successfully */
	PARSEHDR_ERROR, /**< key handled, but the value was rejected */
};

/**
 * @brief Dispatch the message-framing / representation headers shared by both
 *        HTTP endpoints: Transfer-Encoding, Content-Length, Content-Type and
 *        Content-Encoding, all recorded on @p p. Factors the framing logic that
 *        would otherwise be duplicated (and could drift) between the two
 *        parse_header callbacks.
 * @return PARSEHDR_UNHANDLED if @p key names none of these (the caller then
 *         tries its endpoint-specific headers); otherwise PARSEHDR_OK or
 *         PARSEHDR_ERROR reflecting the underlying parser.
 */
enum parsehdr_result parsehdr_representation(
	struct http_conn *restrict p, const char *restrict key,
	char *restrict value);

/**
 * @brief Parse Expect header. Only "100-continue" is supported;
 *        sets error status for any other expectation.
 *
 * RFC 9110 §10.1.1: a 100-continue expectation in an HTTP/1.0 request is
 * ignored, so no interim response is ever sent to an HTTP/1.0 client.
 *
 * @param p Parser instance, in request mode
 * @param value Header value
 * @return true if expectation is supported
 */
bool parsehdr_expect(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Append a Connection field-line value to a combined token list.
 *
 * Comma-joins repeated field lines (RFC 9110 §5.3) into @p store. On entry
 * @p len is the current combined length (0 to start a fresh list).
 *
 * @param store  Combined-value buffer, NUL-terminated on success.
 * @param cap  Capacity of @p store in bytes.
 * @param len  In/out combined length, advanced past the appended value.
 * @param value  Field-line value to append.
 * @return false if the combined value would not fit in @p store.
 */
bool http_connection_join(
	char *restrict store, size_t cap, size_t *restrict len,
	const char *restrict value);

/**
 * @brief Record a Connection field line for hop-by-hop token lookup.
 *
 * RFC 9110 §5.3: repeated field lines combine into one ordered token list. The
 * first line is referenced in place; further lines are comma-joined into the
 * connection's bounded store.
 *
 * @return false if the combined value overflows the store, true otherwise.
 */
bool parsehdr_connection(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Compare two HTTP tokens case-insensitively.
 *
 * Field names, coding names, auth-schemes and the other tokens RFC 9110 §5.1
 * makes case-insensitive fold in ASCII only, whatever LC_CTYPE says; use this
 * rather than the locale-dependent strcasecmp().
 *
 * @return true if @p a and @p b are equal ignoring ASCII case.
 */
bool http_token_equal(const char *restrict a, const char *restrict b);

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

/**
 * @brief Return true if @p connection (a Connection header value) lists the
 * field name @p key as a hop-by-hop token (case-insensitive).
 *
 * @param connection Connection header value, or NULL (treated as no tokens).
 * @param key Field name to search for.
 */
bool http_connection_lists(
	const char *restrict connection, const char *restrict key);

/** @brief Write an HTTP error response page into @p p's write buffer. */
void http_resp_errpage(struct http_conn *restrict p, const uint_fast16_t code);

/**
 * @brief Create a decompressing stream reader over a content buffer.
 * @param buf Content buffer to read from
 * @param len Length of content buffer
 * @param encoding Content encoding type
 * @return Stream for reading decoded content, or NULL on error
 */
struct io_stream *content_reader(
	const void *restrict buf, const size_t len,
	const enum content_encodings encoding);

/**
 * @brief Create a content_reader() over an optional content vbuffer.
 *
 * Content-Length: 0 leaves @p cbuf unallocated; io_memreader() requires a
 * non-NULL buffer even for a zero-length read, so a NULL @p cbuf reads as "".
 * @param cbuf Content buffer, or NULL for an empty body
 * @param encoding Content encoding type
 * @return Stream for reading decoded content, or NULL on error
 */
struct io_stream *content_reader_vbuf(
	const struct vbuffer *restrict cbuf, enum content_encodings encoding);

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
struct io_stream *content_writer(
	struct vbuffer **restrict pvbuf, const size_t bufsize,
	const enum content_encodings encoding);

/**
 * @brief Begin HTTP response header (status line + Date header).
 *
 * RFC 9110 §6.6.1: Date is omitted when http_date() finds no IMF-fixdate
 * rendering of the current time, as http_error() does, since an empty
 * field value is not a valid HTTP-date.
 *
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
			(buf), "HTTP/1.1 %" PRIuFAST16 " %s\r\n",              \
			(uint_fast16_t)(code), status ? status : "");          \
		if (date_len > 0) {                                            \
			BUF_APPENDF(                                           \
				(buf), "Date: %.*s\r\n", (int)date_len,        \
				date_str);                                     \
		}                                                              \
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
