/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "io/stream.h"
#include "utils/testing.h"

#include <fcntl.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct header_cb_ctx {
	struct http_parser *p;
	bool reject;
};

static bool write_all(const int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		const ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (n == 0) {
			return false;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return true;
}

static ssize_t recv_nowait(const int fd, void *buf, const size_t len)
{
	for (;;) {
		const ssize_t n = recv(fd, buf, len, MSG_DONTWAIT);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return n;
	}
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
		return false;
	}
	return true;
}

static bool parse_header_cb(void *ctx, const char *key, char *value)
{
	struct header_cb_ctx *const c = ctx;
	if (c->reject) {
		return false;
	}

	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(c->p, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(c->p, value);
	}
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(c->p, value);
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(c->p, value);
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(c->p, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		return parsehdr_expect(c->p, value);
	}
	return true;
}

static void parser_init_for_test(
	struct http_parser *restrict p, const int fd,
	const enum http_parser_state mode, struct header_cb_ctx *restrict cb)
{
	*cb = (struct header_cb_ctx){
		.p = p,
		.reject = false,
	};
	const struct http_parsehdr_cb on_header = {
		.func = parse_header_cb,
		.ctx = cb,
	};
	http_parser_init(p, fd, mode, on_header);
}

static bool stream_read_exact(
	struct stream *restrict r, unsigned char *restrict buf,
	const size_t want)
{
	size_t got = 0;
	while (got < want) {
		size_t n = want - got;
		if (stream_read(r, buf + got, &n) != 0) {
			return false;
		}
		if (n == 0) {
			break;
		}
		got += n;
	}
	return got == want;
}

static bool stream_write_all(
	struct stream *restrict w, const void *restrict data, const size_t len)
{
	size_t n = len;
	if (stream_write(w, data, &n) != 0) {
		return false;
	}
	return n == len;
}

T_DECLARE_CASE(http_parser_init_request)
{
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };

	parser_init_for_test(&p, 7, STATE_PARSE_REQUEST, &cb);
	T_EXPECT_EQ(p.state, STATE_PARSE_REQUEST);
	T_EXPECT_EQ(p.fd, 7);
	T_EXPECT_EQ(p.http_status, HTTP_BAD_REQUEST);
	T_EXPECT(p.next == NULL);
	T_EXPECT(p.cbuf == NULL);
}

T_DECLARE_CASE(http_parser_init_response)
{
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };

	parser_init_for_test(&p, 8, STATE_PARSE_RESPONSE, &cb);
	T_EXPECT_EQ(p.state, STATE_PARSE_RESPONSE);
	T_EXPECT_EQ(p.fd, 8);
}

T_DECLARE_CASE(parsehdr_accept_te_cases)
{
	struct http_parser p = { 0 };

	{
		char value[] = "   ";
		T_EXPECT(parsehdr_accept_te(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.accept, TENCODING_NONE);
	}
	{
		char value[] = " chunked ";
		T_EXPECT(parsehdr_accept_te(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.accept, TENCODING_CHUNKED);
	}
	{
		char value[] = "gzip";
		T_EXPECT(!parsehdr_accept_te(&p, value));
	}
}

T_DECLARE_CASE(parsehdr_transfer_encoding_cases)
{
	struct http_parser p = { 0 };

	{
		char value[] = "";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_NONE);
	}
	{
		char value[] = "chunked";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	}
	{
		char value[] = "deflate";
		T_EXPECT(!parsehdr_transfer_encoding(&p, value));
	}
}

T_DECLARE_CASE(parsehdr_accept_encoding_cases)
{
	struct http_parser p = { 0 };

	{
		char value[] = "*";
		T_EXPECT(parsehdr_accept_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		char value[] = "gzip;q=0.5, DEFLATE;q=0.8";
		T_EXPECT(parsehdr_accept_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		char value[] = "gzip,br";
		T_EXPECT(!parsehdr_accept_encoding(&p, value));
	}
}

T_DECLARE_CASE(parsehdr_content_length_cases)
{
	struct http_parser p = { 0 };
	p.msg.req.method = "GET";

	T_EXPECT(parsehdr_content_length(&p, "0"));
	T_EXPECT(p.hdr.content.has_length);
	T_EXPECT_EQ(p.hdr.content.length, 0);

	T_EXPECT(parsehdr_content_length(&p, "17"));
	T_EXPECT_EQ(p.hdr.content.length, 17);

	T_EXPECT(!parsehdr_content_length(&p, "12x"));

	p.msg.req.method = "CONNECT";
	T_EXPECT(!parsehdr_content_length(&p, "1"));
}

T_DECLARE_CASE(parsehdr_content_encoding_cases)
{
	struct http_parser p = { 0 };

	T_EXPECT(parsehdr_content_encoding(&p, "deflate"));
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_DEFLATE);

	T_EXPECT(parsehdr_content_encoding(&p, "GZIP"));
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);

	T_EXPECT(!parsehdr_content_encoding(&p, "br"));
	T_EXPECT_EQ(p.http_status, HTTP_UNSUPPORTED_MEDIA_TYPE);
}

T_DECLARE_CASE(parsehdr_expect_cases)
{
	struct http_parser p = { 0 };

	{
		char value[] = " 100-Continue ";
		T_EXPECT(parsehdr_expect(&p, value));
		T_EXPECT(p.expect_continue);
	}
	{
		char value[] = "100-digest";
		p.expect_continue = false;
		T_EXPECT(!parsehdr_expect(&p, value));
		T_EXPECT(!p.expect_continue);
		T_EXPECT_EQ(p.http_status, HTTP_EXPECTATION_FAILED);
	}
}

T_DECLARE_CASE(content_reader_none)
{
	static const unsigned char input[] = "hello";
	unsigned char output[sizeof(input)] = { 0 };
	struct stream *r = content_reader(input, sizeof(input), CENCODING_NONE);

	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);
}

T_DECLARE_CASE(content_reader_gzip)
{
	static const unsigned char gzip_data[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86,
		0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	};
	static const unsigned char expected[] = { 'h', 'e', 'l', 'l', 'o' };
	unsigned char output[sizeof(expected)] = { 0 };
	struct stream *r =
		content_reader(gzip_data, sizeof(gzip_data), CENCODING_GZIP);
	bool ok = false;
	int rc = -1;

	T_CHECK(r != NULL);
	ok = stream_read_exact(r, output, sizeof(output));
	rc = stream_close(r);
	T_EXPECT(ok);
	T_EXPECT_MEMEQ(output, expected, sizeof(expected));
	T_EXPECT_EQ(rc, 0);
}

T_DECLARE_CASE(content_writer_roundtrip_none)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-none";
	unsigned char output[sizeof(input)] = { 0 };

	struct stream *w = content_writer(&vbuf, 64, CENCODING_NONE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(vbuf != NULL);
	T_EXPECT(VBUF_LEN(vbuf) >= sizeof(input));

	struct stream *r =
		content_reader(VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_NONE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(content_writer_roundtrip_deflate)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-deflate";
	unsigned char output[sizeof(input)] = { 0 };

	struct stream *w = content_writer(&vbuf, 64, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(vbuf != NULL);

	struct stream *r = content_reader(
		VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_DEFLATE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(http_resp_established_success)
{
	int sv[2] = { -1, -1 };
	unsigned char rsp[128] = { 0 };
	struct http_parser p = { 0 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	p.fd = sv[0];
	T_EXPECT(http_resp_established(&p));

	const ssize_t n = recv_nowait(sv[1], rsp, sizeof(rsp));
	T_EXPECT(n > 0);
	T_EXPECT(
		memmem(rsp, (size_t)n, "200 Connection established", 26) !=
		NULL);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_resp_established_failure)
{
	struct http_parser p = {
		.fd = -1,
	};

	T_EXPECT(!http_resp_established(&p));
}

T_DECLARE_CASE(http_resp_errpage_normal_and_fallback)
{
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };

	parser_init_for_test(&p, -1, STATE_PARSE_REQUEST, &cb);
	p.cbuf = VBUF_NEW(16);
	T_CHECK(p.cbuf != NULL);
	VBUF_APPENDSTR(p.cbuf, "dummy");

	http_resp_errpage(&p, HTTP_BAD_REQUEST);
	T_EXPECT(p.cbuf == NULL);
	T_EXPECT(p.wbuf.len > 0);
	T_EXPECT(memmem(p.wbuf.data, p.wbuf.len, "HTTP/1.1 400", 12) != NULL);

	p.wbuf.cap = 32;
	http_resp_errpage(&p, HTTP_BAD_REQUEST);
	T_EXPECT(
		memmem(p.wbuf.data, p.wbuf.len, "Connection: close", 17) !=
		NULL);
}

T_DECLARE_CASE(http_parser_recv_request_ok)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET /hello HTTP/1.1\r\n"
				  "Host: test\r\n"
				  "\r\n";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_STREQ(p.msg.req.method, "GET");
	T_EXPECT_STREQ(p.msg.req.url, "/hello");

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_response_ok)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char rsp[] = "HTTP/1.1 204 No Content\r\n"
				  "Date: Wed, 01 Jan 2025 00:00:00 GMT\r\n"
				  "\r\n";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_RESPONSE, &cb);

	T_CHECK(write_all(sv[1], rsp, sizeof(rsp) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_STREQ(p.msg.rsp.version, "HTTP/1.1");
	T_EXPECT_STREQ(p.msg.rsp.code, "204");
	T_EXPECT_STREQ(p.msg.rsp.status, "No Content");

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_bad_version)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET / HTTP/2.0\r\n\r\n";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), -1);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_incremental)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "GET / HTTP/1.1\r\n"
				   "Host: a\r\n";
	static const char req2[] = "\r\n";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 1);
	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_content_incomplete_then_complete)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n"
				   "he";
	static const char req2[] = "llo";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 1);
	T_CHECK(p.cbuf != NULL);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 2);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 5);
	T_EXPECT_MEMEQ(VBUF_DATA(p.cbuf), "hello", 5);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_expect_continue)
{
	int sv[2] = { -1, -1 };
	unsigned char rsp[128] = { 0 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\n"
				   "Expect: 100-continue\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n";
	static const char req2[] = "hello";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 1);
	T_EXPECT(p.expect_continue);

	const ssize_t n = recv_nowait(sv[1], rsp, sizeof(rsp));
	T_EXPECT(n > 0);
	T_EXPECT(memmem(rsp, (size_t)n, "100 Continue", 12) != NULL);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_content_early_eof)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "POST /x HTTP/1.1\r\n"
				  "Content-Length: 5\r\n"
				  "\r\n"
				  "he";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 1);
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	T_EXPECT_EQ(http_parser_recv(&p), -1);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_parser_recv_header_callback_reject)
{
	int sv[2] = { -1, -1 };
	struct http_parser p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET /x HTTP/1.1\r\n"
				  "Host: reject\r\n"
				  "\r\n";

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	parser_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);
	cb.reject = true;

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_parser_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, http_parser_init_request);
	T_RUN_CASE(t, http_parser_init_response);
	T_RUN_CASE(t, parsehdr_accept_te_cases);
	T_RUN_CASE(t, parsehdr_transfer_encoding_cases);
	T_RUN_CASE(t, parsehdr_accept_encoding_cases);
	T_RUN_CASE(t, parsehdr_content_length_cases);
	T_RUN_CASE(t, parsehdr_content_encoding_cases);
	T_RUN_CASE(t, parsehdr_expect_cases);
	T_RUN_CASE(t, content_reader_none);
	T_RUN_CASE(t, content_reader_gzip);
	T_RUN_CASE(t, content_writer_roundtrip_none);
	T_RUN_CASE(t, content_writer_roundtrip_deflate);
	T_RUN_CASE(t, http_resp_established_success);
	T_RUN_CASE(t, http_resp_established_failure);
	T_RUN_CASE(t, http_resp_errpage_normal_and_fallback);
	T_RUN_CASE(t, http_parser_recv_request_ok);
	T_RUN_CASE(t, http_parser_recv_response_ok);
	T_RUN_CASE(t, http_parser_recv_bad_version);
	T_RUN_CASE(t, http_parser_recv_incremental);
	T_RUN_CASE(t, http_parser_recv_content_incomplete_then_complete);
	T_RUN_CASE(t, http_parser_recv_expect_continue);
	T_RUN_CASE(t, http_parser_recv_content_early_eof);
	T_RUN_CASE(t, http_parser_recv_header_callback_reject);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
