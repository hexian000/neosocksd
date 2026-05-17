#include "conf.h"
#include "dialer.h"
#include "proto/codec.h"
#include "proto/http.h"
#include "proto/socks.h"
#include "ruleset.h"
#include "server.h"
#include "socks.h"
#include "transfer.h"
#include "util.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_ITERATIONS 1000
#define FUZZ_MAX_CODEC_INPUT 512
#define FUZZ_MAX_HEADER_VALUE 256
#define FUZZ_MAX_HTTP_INPUT 1024
#define FUZZ_MAX_SOCKS_INPUT 512
#define FUZZ_MAX_STREAM_OUTPUT 65536

struct prng {
	uint64_t state[4];
};

static uint64_t fuzz_seed = UINT64_C(0x42);
static size_t fuzz_iterations = FUZZ_DEFAULT_ITERATIONS;

static struct config test_conf = {
	.timeout = 1.0,
	.auth_required = false,
	.socks5_bind = false,
	.socks5_udp = false,
};

static uint64_t splitmix64_next(uint64_t *restrict state)
{
	uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
	z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

static void prng_seed(struct prng *restrict p, const uint64_t seed)
{
	uint64_t state = seed;
	for (size_t i = 0; i < 4; i++) {
		p->state[i] = splitmix64_next(&state);
	}
}

static uint64_t rotl64(const uint64_t x, const int k)
{
	return (x << k) | (x >> (64 - k));
}

static uint64_t prng_next(struct prng *restrict p)
{
	const uint64_t result = rotl64(p->state[1] * 5, 7) * 9;
	const uint64_t t = p->state[1] << 17;

	p->state[2] ^= p->state[0];
	p->state[3] ^= p->state[1];
	p->state[1] ^= p->state[2];
	p->state[0] ^= p->state[3];
	p->state[2] ^= t;
	p->state[3] = rotl64(p->state[3], 45);

	return result;
}

static void
prng_fill(struct prng *restrict p, void *restrict buf, const size_t len)
{
	unsigned char *restrict out = buf;
	size_t pos = 0;
	while (pos < len) {
		uint64_t value = prng_next(p);
		for (size_t i = 0; i < sizeof(value) && pos < len; i++) {
			out[pos++] = (unsigned char)(value & UINT64_C(0xff));
			value >>= 8;
		}
	}
}

static size_t
prng_size(struct prng *restrict p, const size_t min, const size_t max)
{
	if (max <= min) {
		return min;
	}
	return min + (size_t)(prng_next(p) % (uint64_t)(max - min + 1));
}

static bool prng_bool(struct prng *restrict p)
{
	return (prng_next(p) & 1) != 0;
}

static bool read_uintmax_env(const char *restrict name, uintmax_t *restrict out)
{
	const char *const value = getenv(name);
	if (value == NULL || value[0] == '\0') {
		return false;
	}

	errno = 0;
	char *end = NULL;
	const uintmax_t parsed = strtoumax(value, &end, 0);
	if (errno != 0 || end == value || *end != '\0') {
		return false;
	}
	*out = parsed;
	return true;
}

static uint64_t read_seed(void)
{
	uintmax_t value;
	if (!read_uintmax_env("FUZZ_SEED", &value) || value > UINT64_MAX) {
		return UINT64_C(0x42);
	}
	return (uint64_t)value;
}

static size_t read_iterations(void)
{
	uintmax_t value;
	if (!read_uintmax_env("FUZZ_ITER", &value) || value > SIZE_MAX) {
		return FUZZ_DEFAULT_ITERATIONS;
	}
	return (size_t)value;
}

static uint64_t fuzz_case_seed(const uint64_t tag)
{
	return fuzz_seed ^ (tag * UINT64_C(0x9e3779b97f4a7c15));
}

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

static void close_checked(int *restrict fd)
{
	if (*fd < 0) {
		return;
	}
	const int closing = *fd;
	*fd = -1;
	T_CHECK(close(closing) == 0);
}

static void drain_stream(struct stream *restrict s)
{
	size_t total = 0;
	for (;;) {
		unsigned char out[1024];
		size_t len = sizeof(out);
		const int err = stream_read(s, out, &len);
		if (err != 0 || len == 0) {
			break;
		}
		total += len;
		if (total >= FUZZ_MAX_STREAM_OUTPUT) {
			break;
		}
	}
}

typedef struct stream *(*codec_reader_fn)(struct stream *base);

static void
fuzz_codec_reader(struct prng *restrict p, codec_reader_fn new_reader)
{
	unsigned char input[FUZZ_MAX_CODEC_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	struct stream *const base = io_memreader(input, len);
	T_CHECK(base != NULL);
	struct stream *const reader = new_reader(base);
	if (reader == NULL) {
		return;
	}
	drain_stream(reader);
	/* Malformed fuzz inputs may be rejected during close-time validation. */
	(void)stream_close(reader);
}

static void
fuzz_ascii_string(struct prng *restrict p, char *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (char)(0x20 + (prng_next(p) % 0x5f));
		if (buf[i] == '\0') {
			buf[i] = 'x';
		}
	}
	buf[len] = '\0';
}

struct header_cb_ctx {
	struct http_conn *conn;
};

static bool parse_header_cb(void *ctx, const char *key, char *value)
{
	struct header_cb_ctx *const c = ctx;
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(c->conn, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(c->conn, value);
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		return parsehdr_expect(c->conn, value);
	}
	if (strcasecmp(key, "Connection") == 0) {
		return parsehdr_connection(c->conn, value);
	}
	return true;
}

static void
fuzz_http_conn(struct prng *restrict p, const enum http_conn_state mode)
{
	int sv[2] = { -1, -1 };
	struct http_conn conn = { 0 };
	struct header_cb_ctx cbctx = {
		.conn = &conn,
	};
	const struct http_parsehdr_cb cb = {
		.func = parse_header_cb,
		.ctx = &cbctx,
	};
	unsigned char input[FUZZ_MAX_HTTP_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(write_all(sv[1], input, len));
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	http_conn_init(&conn, sv[0], mode, cb, NULL, NULL);

	for (size_t i = 0; i < 8; i++) {
		const int ret = http_conn_recv(&conn);
		if (ret != 1) {
			break;
		}
	}

	VBUF_FREE(conn.cbuf);
	close_checked(&sv[0]);
	close_checked(&sv[1]);
}

static void fuzz_parsehdr_value(
	struct prng *restrict p, char *restrict value, const size_t len)
{
	fuzz_ascii_string(p, value, len);
	if (len > 0 && prng_bool(p)) {
		value[prng_size(p, 0, len - 1)] = ',';
	}
	if (len > 0 && prng_bool(p)) {
		value[prng_size(p, 0, len - 1)] = ';';
	}
}

static void fuzz_connection_tokens(const char *restrict value)
{
	const char *cursor = value;
	for (size_t i = 0; i <= FUZZ_MAX_HEADER_VALUE; i++) {
		const char *tok;
		size_t toklen;
		const char *const next =
			parsehdr_connection_token(cursor, &tok, &toklen);
		if (next == NULL || *next == '\0') {
			break;
		}
		if (next == cursor) {
			break;
		}
		cursor = next;
	}
}

static void fuzz_http_headers_once(struct prng *restrict p)
{
	char value[FUZZ_MAX_HEADER_VALUE + 1];
	char copy[FUZZ_MAX_HEADER_VALUE + 1];
	const size_t len = prng_size(p, 0, FUZZ_MAX_HEADER_VALUE);
	fuzz_parsehdr_value(p, value, len);

	struct http_conn conn = { 0 };
	http_conn_init(
		&conn, -1, STATE_PARSE_REQUEST, (struct http_parsehdr_cb){ 0 },
		NULL, NULL);
	conn.msg.req.method = "";

#define CALL_PARSEHDR(fn)                                                      \
	do {                                                                   \
		(void)memcpy(copy, value, len + 1);                            \
		(void)fn(&conn, copy);                                         \
	} while (0)
	CALL_PARSEHDR(parsehdr_accept_te);
	CALL_PARSEHDR(parsehdr_transfer_encoding);
	CALL_PARSEHDR(parsehdr_accept_encoding);
	CALL_PARSEHDR(parsehdr_content_length);
	CALL_PARSEHDR(parsehdr_content_encoding);
	CALL_PARSEHDR(parsehdr_expect);
	CALL_PARSEHDR(parsehdr_connection);
#undef CALL_PARSEHDR
	fuzz_connection_tokens(value);
}

const char *dialer_strerror(const enum dialer_error err)
{
	UNUSED(err);
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	UNUSED(base);
	if (num_proxy >
	    (SIZE_MAX - sizeof(struct dialreq)) / sizeof(struct proxyreq)) {
		return NULL;
	}
	struct dialreq *const req =
		calloc(1, sizeof(*req) + num_proxy * sizeof(struct proxyreq));
	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = num_proxy;
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	UNUSED(req);
	UNUSED(proxy_uri);
	UNUSED(urilen);
	return false;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	UNUSED(addr);
	UNUSED(csv);
	return NULL;
}

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	UNUSED(s);
	UNUSED(maxlen);
	UNUSED(r);
	return -1;
}

void dialreq_free(struct dialreq *req)
{
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	UNUSED(addr);
	UNUSED(s);
	UNUSED(len);
	return false;
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	UNUSED(addr);
	UNUSED(sa);
	UNUSED(len);
	return false;
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	*dst = *src;
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	switch (addr->type) {
	case ATYP_INET: {
		const unsigned char *const p = (const unsigned char *)&addr->in;
		return snprintf(
			s, maxlen, "%u.%u.%u.%u:%" PRIuLEAST16,
			(unsigned int)p[0], (unsigned int)p[1],
			(unsigned int)p[2], (unsigned int)p[3], addr->port);
	}
	case ATYP_INET6:
		return snprintf(s, maxlen, "[::]:%" PRIuLEAST16, addr->port);
	case ATYP_DOMAIN:
		return snprintf(
			s, maxlen, "%.*s:%" PRIuLEAST16, (int)addr->domain.len,
			addr->domain.name, addr->port);
	default:
		break;
	}
	return snprintf(s, maxlen, "?:%" PRIuLEAST16, addr->port);
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uintmax_t *byt_sent, uintmax_t *byt_recv)
{
	(void)byt_sent;
	(void)byt_recv;
	(void)memset(d, 0, sizeof(*d));
	d->finish_cb = *callback;
	d->err = DIALER_OK;
	d->syserr = 0;
	d->dialed_fd = -1;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver,
	struct server *server)
{
	UNUSED(req);
	UNUSED(conf);
	UNUSED(resolver);
	UNUSED(server);
	d->err = DIALER_ERR_CONNECT;
	d->syserr = ECONNREFUSED;
	d->finish_cb.func(loop, d->finish_cb.data, -1);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	UNUSED(d);
	UNUSED(loop);
}

struct transfer *
transfer_new(struct ev_loop *restrict loop, const unsigned int nworkers)
{
	UNUSED(loop);
	UNUSED(nworkers);
	static int token;
	return (struct transfer *)&token;
}

void transfer_free(struct transfer *restrict xfer)
{
	UNUSED(xfer);
}

bool transfer_serve(
	struct transfer *restrict xfer, const int acc_fd, const int dial_fd,
	const struct transfer_opts *restrict opts)
{
	UNUSED(xfer);
	close_checked(&(int){ acc_fd });
	close_checked(&(int){ dial_fd });
#if WITH_THREADS
	atomic_fetch_sub_explicit(opts->num_sessions, 1, memory_order_relaxed);
#else
	(*opts->num_sessions)--;
#endif
	return true;
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	UNUSED(loop);
	UNUSED(state);
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(state);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	UNUSED(callback);
	return false;
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(state);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	UNUSED(callback);
	return false;
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(state);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	UNUSED(callback);
	return false;
}

static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->xfer = transfer_new(s->loop, 1);
	s->basereq = NULL;
#if WITH_RULESET
	s->ruleset = NULL;
#endif
}

static size_t fuzz_append_random(
	struct prng *restrict p, unsigned char *restrict buf, size_t len,
	const size_t cap, const size_t max_tail)
{
	const size_t space = cap - len;
	const size_t tail =
		prng_size(p, 0, space < max_tail ? space : max_tail);
	prng_fill(p, buf + len, tail);
	return len + tail;
}

static void fuzz_printable(
	struct prng *restrict p, unsigned char *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)('a' + (prng_next(p) % 26));
	}
}

static size_t make_socks5_ipv4(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_NOAUTH,
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_domain(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_NOAUTH,
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_DOMAIN,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	const size_t domain_len = prng_size(p, 1, 32);
	buf[len++] = (unsigned char)domain_len;
	fuzz_printable(p, buf + len, domain_len);
	len += domain_len;
	prng_fill(p, buf + len, 2);
	len += 2;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_userpass(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_USERPASS,
		0x01,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	const size_t user_len = prng_size(p, 1, 16);
	const size_t pass_len = prng_size(p, 1, 16);
	buf[len++] = (unsigned char)user_len;
	fuzz_printable(p, buf + len, user_len);
	len += user_len;
	buf[len++] = (unsigned char)pass_len;
	fuzz_printable(p, buf + len, pass_len);
	len += pass_len;
	static const unsigned char req[] = {
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf + len, req, sizeof(req));
	len += sizeof(req);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_unsupported(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,		0x01, SOCKS5AUTH_NOAUTH, SOCKS5,
		SOCKS5CMD_BIND, 0x00, SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks4(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	buf[0] = SOCKS4;
	buf[1] = SOCKS4CMD_CONNECT;
	prng_fill(p, buf + 2, 6);
	size_t len = SOCKS4_HDR_LEN;
	const size_t user_len = prng_size(p, 0, 32);
	fuzz_printable(p, buf + len, user_len);
	len += user_len;
	buf[len++] = '\0';
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks4a(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	buf[0] = SOCKS4;
	buf[1] = SOCKS4CMD_CONNECT;
	prng_fill(p, buf + 2, 2);
	buf[4] = 0x00;
	buf[5] = 0x00;
	buf[6] = 0x00;
	buf[7] = 0x01;
	size_t len = SOCKS4_HDR_LEN;
	buf[len++] = 'u';
	buf[len++] = '\0';
	const size_t domain_len = prng_size(p, 1, 32);
	fuzz_printable(p, buf + len, domain_len);
	len += domain_len;
	buf[len++] = '\0';
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks_payload(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	switch (prng_next(p) % 8) {
	case 0: {
		const size_t len = prng_size(p, 0, cap);
		prng_fill(p, buf, len);
		return len;
	}
	case 1:
		return make_socks5_ipv4(p, buf, cap);
	case 2:
		return make_socks5_domain(p, buf, cap);
	case 3:
		return make_socks5_userpass(p, buf, cap);
	case 4:
		return make_socks5_unsupported(p, buf, cap);
	case 5:
		return make_socks4(p, buf, cap);
	case 6:
		return make_socks4a(p, buf, cap);
	default:
		buf[0] = SOCKS5;
		return fuzz_append_random(p, buf, 1, cap, 32);
	}
}

static void fuzz_socks_once(struct prng *restrict p)
{
	int sv[2] = { -1, -1 };
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};
	unsigned char input[FUZZ_MAX_SOCKS_INPUT];
	const size_t len = make_socks_payload(p, input, sizeof(input));

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.timeout = 1.0;
	test_conf.auth_required = prng_bool(p);
	test_conf.socks5_bind = false;
	test_conf.socks5_udp = false;
	test_server_init(&s);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	socks_serve(&s, loop, sv[0], (const struct sockaddr *)&sa);
	sv[0] = -1;
	T_CHECK(write_all(sv[1], input, len));
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	ev_run(loop, 0);

	close_checked(&sv[1]);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(fuzz_inflate)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(1));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_inflate_reader);
	}
}

T_DECLARE_CASE(fuzz_zlib)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(2));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_zlib_reader);
	}
}

T_DECLARE_CASE(fuzz_gzip)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(3));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_gzip_reader);
	}
}

T_DECLARE_CASE(fuzz_http_req)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(4));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_REQUEST);
	}
}

T_DECLARE_CASE(fuzz_http_resp)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(5));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_RESPONSE);
	}
}

T_DECLARE_CASE(fuzz_parsehdr)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(6));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_headers_once(&p);
	}
}

T_DECLARE_CASE(fuzz_socks)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(7));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_socks_once(&p);
	}
}

#define ALL_TESTS(X)                                                           \
	X(fuzz_inflate)                                                        \
	X(fuzz_zlib)                                                           \
	X(fuzz_gzip)                                                           \
	X(fuzz_http_req)                                                       \
	X(fuzz_http_resp)                                                      \
	X(fuzz_parsehdr)                                                       \
	X(fuzz_socks)

int main(void)
{
	fuzz_seed = read_seed();
	fuzz_iterations = read_iterations();
	(void)fprintf(
		stderr, "fuzz seed=0x%016" PRIx64 " iter=%zu\n", fuzz_seed,
		fuzz_iterations);

	T_DECLARE_CTX(t);
#define RUN_TEST(name) T_RUN_CASE(t, name);
	ALL_TESTS(RUN_TEST)
#undef RUN_TEST
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
