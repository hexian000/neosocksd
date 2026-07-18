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
extern const char *const http_content_encoding_str[];

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

/**
 * @brief A resumable, buffer-agnostic HTTP message-head parser.
 *
 * Parses the start line (request or response) once, then each header field,
 * invoking a callback per field, over a caller-owned NUL-terminated buffer that
 * may grow between calls. Unlike ::http_conn it owns no buffer and drives no
 * state machine, so it suits a caller that shares one buffer between the head
 * and a streaming body (the proxy response path). It holds only a parse cursor,
 * so it can be re-run after more bytes are appended.
 */
struct http_reader {
	size_t pos; /**< parse cursor into the buffer */
	bool line_done; /**< start line parsed */
};

/** @brief Outcome of ::http_reader_parse. */
enum http_reader_state {
	HTTP_READER_OK, /**< head complete; @c pos points at the body start */
	HTTP_READER_MORE, /**< need more bytes appended to the buffer */
	HTTP_READER_ERROR, /**< malformed line/header, or on_header rejected */
};

/** @brief Reset a reader to parse a fresh message from the buffer start. */
void http_reader_init(struct http_reader *restrict r);

/**
 * @brief Parse as far as possible from @c base + @c pos.
 *
 * @param r Reader state (cursor); updated in place.
 * @param base Buffer start; must be NUL-terminated at the end of the currently
 *     available bytes.
 * @param msg Receives the parsed start line.
 * @param is_request true to validate/interpret a request line, false for a
 *     response line (selects the version field to version-check).
 * @param on_header Invoked once per header field; returning false aborts with
 *     HTTP_READER_ERROR.
 * @return See ::enum http_reader_state.
 */
enum http_reader_state http_reader_parse(
	struct http_reader *restrict r, char *restrict base,
	struct http_message *restrict msg, bool is_request,
	struct http_parsehdr_cb on_header);

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
 *
 * Only a Content-Length delimited body is framed, into `cbuf`. A
 * `Transfer-Encoding: chunked` message parses to STATE_PARSE_OK with
 * `cbuf == NULL` and its body left unconsumed in `rbuf`: the one caller that
 * accepts chunked (the proxy's proxy_pass) dechunks it itself through
 * http_framer, so framing it here would be wasted work.
 *
 * A caller that consumes `cbuf` must therefore reject chunked itself, or it
 * will silently see an empty body. Both do: api_server's `restapi_check`
 * answers 501 for every REST endpoint, and api_client's `on_http_client_done`
 * reports an error for a chunked rpcall/invoke response. Check
 * `hdr.transfer.encoding` before relying on `cbuf`.
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

void http_body_init(
	struct http_body *restrict d, const enum http_body_mode mode,
	const size_t content_length);

/**
 * @brief Feed data to a body parser.
 * @param len Input: bytes available in data. Output: bytes actually
 *     consumed as body content, which may be less than the input value
 *     when the body (e.g. a chunked terminator) ends partway through --
 *     the remaining bytes belong to whatever follows and are left for
 *     the caller to reprocess, not treated as a parse failure.
 * @return false only on a genuine parse error or a nonzero-length call
 *     after the body is already done. A zero-length call (*len == 0) is
 *     always a no-op that returns true, even after the body has finished.
 */
bool http_body_consume(
	struct http_body *restrict d, const unsigned char *restrict data,
	size_t *restrict len, const struct http_body_data_cb on_data);

bool http_body_finish(struct http_body *restrict d);

/** Maximum length of a chunk-size line "<hex>\r\n" (16 hex digits + CRLF). */
#define HTTP_CHUNK_HEADER_MAX (16 + 2)

/** Chunked-transfer terminator: the final empty chunk (no trailers). */
#define HTTP_CHUNK_TERMINATOR "0\r\n\r\n"

/**
 * @brief Write a chunked-transfer chunk-size line "<hex>\r\n" for a chunk of
 * @p datalen bytes (the inverse of the http_body chunked dechunker).
 * @param buf Destination; must hold at least HTTP_CHUNK_HEADER_MAX bytes.
 * @param datalen Chunk data length; must be nonzero (the terminator is
 *     HTTP_CHUNK_TERMINATOR).
 * @return Number of bytes written (no NUL terminator).
 */
size_t http_chunk_header(char *restrict buf, size_t datalen);

/** Bytes moved through the framer per input/output pass. */
#define HTTP_FRAMER_BUFSIZE 16384
/** Reserved prefix room in the output buffer for a prepended chunk-size line. */
#define HTTP_FRAMER_HDR_ROOM HTTP_CHUNK_HEADER_MAX

/**
 * @brief The next action a framer needs from its I/O-owning caller.
 * @see http_framer_run
 */
enum http_framer_op {
	HTTP_FRAMER_SEND, /**< framed output ready: drain via http_framer_pending */
	HTTP_FRAMER_FILL, /**< need input: fill via http_framer_inbuf + _filled/_eof */
	HTTP_FRAMER_DONE, /**< body fully framed and drained */
	HTTP_FRAMER_ERROR, /**< malformed input body */
};

/**
 * @brief An I/O-free HTTP body framing filter.
 *
 * Decodes an input body (Content-Length / chunked / EOF / none) via
 * ::http_body and re-encodes it as either chunked (::http_chunk_header) or
 * length-delimited output, one bounded buffer-full at a time. The filter owns
 * its input and output buffers but performs no I/O: the caller reads raw source
 * bytes into the input buffer and drains framed bytes from the output buffer,
 * driven by ::http_framer_run. Input is throttled to the output capacity, so a
 * decode pass can never overflow the output.
 *
 * The struct is transparent so a caller sharing the input buffer with an inline
 * header parser (the proxy response path) can fill @c in directly and hand the
 * leftover body bytes to the filter via ::http_framer_seed.
 */
struct http_framer {
	struct http_body body; /**< input decoder state */
	bool rechunk; /**< true: emit chunked; false: pass length-framed */
	bool done; /**< body decoded, output (incl. terminator) drained */
	bool sending_term; /**< out[] holds the chunked terminator */
	size_t in_pos, in_len; /**< unconsumed raw input in in[] */
	size_t out_pos, out_end; /**< framed output pending in out[] */
	size_t datalen; /**< decoded bytes staged at out[HTTP_FRAMER_HDR_ROOM..] */
	unsigned char in[HTTP_FRAMER_BUFSIZE];
	/* header room + data + trailing CRLF */
	unsigned char out[HTTP_FRAMER_HDR_ROOM + HTTP_FRAMER_BUFSIZE + 2];
};

/**
 * @brief Initialize a framer. Does not touch the input/output byte buffers.
 * @param in_mode Input body framing (::enum http_body_mode).
 * @param content_length Body length for HTTP_BODY_CONTENT_LENGTH (else ignored).
 * @param rechunk true to emit chunked output; false to pass length-framed.
 */
void http_framer_init(
	struct http_framer *restrict f, enum http_body_mode in_mode,
	size_t content_length, bool rechunk);

/**
 * @brief Seed the filter with @p len bytes already present in its input buffer,
 * of which the first @p pos have been consumed (used to adopt body bytes that
 * arrived alongside a header block, or a request readahead).
 */
void http_framer_seed(struct http_framer *restrict f, size_t pos, size_t len);

/**
 * @brief Advance the filter to its next required I/O action.
 * @return HTTP_FRAMER_SEND / _FILL / _DONE / _ERROR (see ::enum http_framer_op).
 */
enum http_framer_op http_framer_run(struct http_framer *restrict f);

/**
 * @brief View the framed output pending to send.
 * @param[out] buf Set to the first unsent byte.
 * @return Number of bytes pending (0 when none).
 */
size_t http_framer_pending(
	const struct http_framer *restrict f,
	const unsigned char **restrict buf);

/** @brief Acknowledge @p n framed output bytes drained by the caller. */
void http_framer_drained(struct http_framer *restrict f, size_t n);

/**
 * @brief Expose the input buffer for a fresh read.
 * @param[out] buf Set to the first byte to fill.
 * @param[out] cap Set to how many bytes may be read (throttled to output
 *     capacity and, for Content-Length, to the remaining body).
 */
void http_framer_inbuf(
	struct http_framer *restrict f, unsigned char **restrict buf,
	size_t *restrict cap);

/** @brief Record @p n bytes read into the input buffer via http_framer_inbuf. */
void http_framer_filled(struct http_framer *restrict f, size_t n);

/**
 * @brief Signal end-of-input (source closed) to the filter.
 * @return true if EOF is a valid body terminus (HTTP_BODY_EOF, now finished);
 *     false if the body was truncated (the caller should fail the exchange).
 */
bool http_framer_eof(struct http_framer *restrict f);

/**
 * @brief Parse TE header, a list of accepted transfer-codings.
 *
 * Sets the accepted encoding to chunked if the list contains that coding.
 * TE only advertises what the client accepts, so an unsupported coding is
 * not an error.
 *
 * @param p Parser instance
 * @param value Header value
 * @return true for any well-formed value
 */
bool parsehdr_accept_te(struct http_conn *restrict p, char *restrict value);

/**
 * @brief Parse Transfer-Encoding header. Currently detects chunked.
 * @param p Parser instance
 * @param value Header value
 * @return true on success; false for a coding that cannot be framed, or for
 *     an ambiguous Content-Length + chunked framing
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

/**
 * @brief Return true if @p connection (a Connection header value) lists the
 * field name @p key as a hop-by-hop token (case-insensitive).
 *
 * @param connection Connection header value, or NULL (treated as no tokens).
 * @param key Field name to search for.
 */
bool http_connection_lists(
	const char *restrict connection, const char *restrict key);

/**
 * @brief Validate an HTTP header field for forwarding.
 *
 * RFC 7230 §3.2.6 / RFC 9110 §5.5: a field name must be tchar-only and a field
 * value must contain no CTL other than HTAB.
 *
 * @return true if both @p key and @p value are well-formed.
 */
bool http_header_field_valid(
	const char *restrict key, const char *restrict value);

/**
 * @brief Normalize "host[:port]" into @p buf, appending ":80" when the port is
 * absent (bracketed IPv6 literals are handled).
 *
 * @param buf Destination buffer.
 * @param cap Capacity of @p buf.
 * @param host Source host, optionally with a port.
 * @return false when @p buf is too small or @p host is malformed.
 */
bool http_hostport_normalize(
	char *restrict buf, size_t cap, const char *restrict host);

/**
 * @brief Append a NUL-terminated string to a fixed buffer, failing instead of
 * truncating.
 *
 * @param buf Destination fixed buffer.
 * @param s String to append.
 * @return false when @p s does not fit in the remaining capacity (the buffer
 *     is left unchanged); true on success.
 */
bool http_append(struct buffer *restrict buf, const char *restrict s);

/** @brief A recorded HTTP header field, for forwarding. */
struct http_header_kv {
	const char *key;
	const char *value;
};

/**
 * @brief Emit recorded end-to-end headers as "key: value\r\n" into @p buf,
 * skipping any field name listed as hop-by-hop in the @p connection header
 * value (see http_connection_lists).
 *
 * @param buf Destination fixed buffer.
 * @param hdr Recorded header fields.
 * @param n Number of fields in @p hdr.
 * @param connection Connection header value, or NULL.
 * @return false on overflow (partial output may have been written); true on
 *     success.
 */
bool http_append_headers(
	struct buffer *restrict buf, const struct http_header_kv *restrict hdr,
	size_t n, const char *restrict connection);

/**
 * @brief Emit the body framing header into @p buf: "Transfer-Encoding:
 * chunked\r\n" when @p chunked, otherwise "Content-Length: N\r\n" when
 * @p clen_known, otherwise nothing.
 *
 * @return false on overflow; true otherwise.
 */
bool http_append_framing(
	struct buffer *restrict buf, bool chunked, bool clen_known,
	size_t content_length);

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
