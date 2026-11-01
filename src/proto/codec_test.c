/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * codec_test - white-box unit tests for proto/codec.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   proto/codec.c    module under test
 * Leaf libraries: csnippets (io/stream, utils/buffer), miniz.
 *
 * CRC calls in codec.c are observed through a test-only compiler alias.
 * Constructor allocations, including io_bufreader, use linker interposition.
 */

#include "codec.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "meta/arraysize.h"
#include "miniz.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - count CRC calls while delegating to the real implementation.
 * ---------------------------------------------------------------------- */

static size_t crc_calls;

mz_ulong test_mz_crc32(mz_ulong crc, const unsigned char *ptr, size_t len);

mz_ulong test_mz_crc32(mz_ulong crc, const unsigned char *ptr, size_t len)
{
	++crc_calls;
	return mz_crc32(crc, ptr, len);
}

static bool constructor_alloc_active;
static size_t constructor_alloc_fail;
static size_t constructor_alloc_calls;
static size_t constructor_free_calls;
static void *constructor_allocations[2];

void *real_constructor_malloc(size_t size) __asm__("__real_malloc");
void real_constructor_free(void *ptr) __asm__("__real_free");
void *test_constructor_malloc(size_t size) __asm__("__wrap_malloc");
void test_constructor_free(void *ptr) __asm__("__wrap_free");

void *test_constructor_malloc(const size_t size)
{
	if (constructor_alloc_active &&
	    ++constructor_alloc_calls == constructor_alloc_fail) {
		errno = ENOMEM;
		return NULL;
	}
	void *const ptr = real_constructor_malloc(size);
	if (constructor_alloc_active && ptr != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(constructor_allocations);
		     ++i) {
			if (constructor_allocations[i] == NULL) {
				constructor_allocations[i] = ptr;
				return ptr;
			}
		}
		T_CHECK(false);
	}
	return ptr;
}

void test_constructor_free(void *const ptr)
{
	if (ptr != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(constructor_allocations);
		     ++i) {
			if (constructor_allocations[i] == ptr) {
				constructor_allocations[i] = NULL;
				++constructor_free_calls;
				break;
			}
		}
	}
	real_constructor_free(ptr);
}

static void constructor_alloc_reset(void *data)
{
	(void)data;
	constructor_alloc_active = false;
	constructor_alloc_fail = 0;
	constructor_alloc_calls = constructor_free_calls = 0;
	for (size_t i = 0; i < ARRAY_SIZE(constructor_allocations); ++i) {
		real_constructor_free(constructor_allocations[i]);
		constructor_allocations[i] = NULL;
	}
}

struct constructor_base {
	struct io_stream s;
	size_t closes;
	size_t writes;
	size_t header_len;
	int write_error;
	unsigned char header[10];
};

static int constructor_base_close(void *data)
{
	struct constructor_base *base = data;
	++base->closes;
	return EIO;
}

static int constructor_base_write(
	void *data, const void *restrict buf, size_t *restrict len)
{
	struct constructor_base *base = data;
	++base->writes;
	T_CHECK(*len >= sizeof(base->header));
	memcpy(base->header, buf, sizeof(base->header));
	*len = base->header_len;
	return base->write_error;
}

static int constructor_base_direct_read(
	void *data, const void **restrict buf, size_t *restrict len)
{
	(void)data;
	*buf = NULL;
	*len = 0;
	return 0;
}

static struct constructor_base constructor_base(const bool direct)
{
	static const struct io_stream_vftable vftable = {
		.write = constructor_base_write,
		.close = constructor_base_close,
	};
	static const struct io_stream_vftable direct_vftable = {
		.direct_read = constructor_base_direct_read,
		.write = constructor_base_write,
		.close = constructor_base_close,
	};
	return (struct constructor_base){
		.s = { .vftable = direct ? &direct_vftable : &vftable },
		.header_len = 10,
	};
}

T_DECLARE_CASE(codec_writer_constructor_allocation_failure_closes_base)
{
	struct io_stream *(*const constructors[])(struct io_stream *) = {
		codec_deflate_writer,
		codec_zlib_writer,
		codec_gzip_writer,
	};
	T_CLEANUP(constructor_alloc_reset, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(constructors); ++i) {
		constructor_alloc_reset(NULL);
		struct constructor_base base = constructor_base(false);
		constructor_alloc_fail = 1;
		constructor_alloc_active = true;
		struct io_stream *const stream = constructors[i](&base.s);
		constructor_alloc_active = false;
		if (stream != NULL) {
			(void)io_stream_close(stream);
		}
		T_EXPECT(stream == NULL);
		T_EXPECT_EQ(constructor_alloc_calls, 1);
		T_EXPECT_EQ(base.closes, 1);
		T_EXPECT_EQ(base.writes, i == 2 ? 1 : 0);
		T_EXPECT_EQ(constructor_free_calls, 0);
		for (size_t j = 0; j < ARRAY_SIZE(constructor_allocations);
		     ++j) {
			T_EXPECT(constructor_allocations[j] == NULL);
		}
	}
}

T_DECLARE_CASE(codec_reader_constructor_allocation_failure_closes_base)
{
	struct io_stream *(*const constructors[])(struct io_stream *) = {
		codec_inflate_reader,
		codec_zlib_reader,
		codec_gzip_reader,
	};
	T_CLEANUP(constructor_alloc_reset, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(constructors); ++i) {
		for (size_t direct = 0; direct < 2; ++direct) {
			const size_t allocations = direct != 0 ? 1 : 2;
			for (size_t fail = 1; fail <= allocations; ++fail) {
				constructor_alloc_reset(NULL);
				struct constructor_base base =
					constructor_base(direct != 0);
				constructor_alloc_fail = fail;
				constructor_alloc_active = true;
				struct io_stream *const stream =
					constructors[i](&base.s);
				constructor_alloc_active = false;
				if (stream != NULL) {
					(void)io_stream_close(stream);
				}
				T_EXPECT(stream == NULL);
				T_EXPECT_EQ(constructor_alloc_calls, fail);
				T_EXPECT_EQ(base.closes, 1);
				T_EXPECT_EQ(base.writes, 0);
				T_EXPECT_EQ(constructor_free_calls, fail - 1);
				for (size_t j = 0;
				     j < ARRAY_SIZE(constructor_allocations);
				     ++j) {
					T_EXPECT(
						constructor_allocations[j] ==
						NULL);
				}
			}
		}
	}
}

T_DECLARE_CASE(codec_gzip_constructor_header_failure_closes_base)
{
	static const unsigned char header[10] = {
		0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff,
	};
	static const size_t lengths[] = { 0, 9, 10 };
	static const int errors[] = { 0, EIO };
	T_CLEANUP(constructor_alloc_reset, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i) {
		for (size_t j = 0; j < ARRAY_SIZE(errors); ++j) {
			if (lengths[i] == sizeof(header) && errors[j] == 0) {
				continue;
			}
			constructor_alloc_reset(NULL);
			struct constructor_base base = constructor_base(false);
			base.header_len = lengths[i];
			base.write_error = errors[j];
			constructor_alloc_active = true;
			struct io_stream *const stream =
				codec_gzip_writer(&base.s);
			constructor_alloc_active = false;
			if (stream != NULL) {
				(void)io_stream_close(stream);
			}
			T_EXPECT(stream == NULL);
			T_EXPECT_EQ(base.closes, 1);
			T_EXPECT_EQ(base.writes, 1);
			T_EXPECT_MEMEQ(base.header, header, sizeof(header));
			T_EXPECT_EQ(constructor_alloc_calls, 0);
		}
	}
}

/* -------------------------------------------------------------------------
 * fuzz - randomized codec inputs are exercised by main_test (fuzz_inflate,
 * fuzz_zlib, fuzz_gzip); none here.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - deterministic round-trip and malformed-input cases.
 * ---------------------------------------------------------------------- */

enum fixture_failure {
	FIXTURE_FAIL_NONE,
	FIXTURE_FAIL_WRITE,
	FIXTURE_FAIL_READ,
	FIXTURE_FAIL_CLOSE,
	FIXTURE_FAIL_LUA_SOURCE,
};

static enum fixture_failure fixture_failure;
static char fixture_failed_path[sizeof(TEST_TMPDIR "/codec_test_XXXXXX")];

static bool fixture_inject_failure(const enum fixture_failure failure)
{
	if (fixture_failure != failure) {
		return false;
	}
	fixture_failure = FIXTURE_FAIL_NONE;
	return true;
}

static bool stream_write_all(
	struct io_stream *restrict s, const void *restrict data,
	const size_t len)
{
	size_t total = 0;
	const unsigned char *p = data;

	while (total < len) {
		size_t n = len - total;
		if (io_stream_write(s, p + total, &n) != 0) {
			return false;
		}
		if (n == 0) {
			return false;
		}
		total += n;
	}
	return !fixture_inject_failure(FIXTURE_FAIL_WRITE);
}

static bool stream_read_exact(
	struct io_stream *restrict s, void *restrict out, const size_t len)
{
	size_t total = 0;
	unsigned char *p = out;

	while (total < len) {
		size_t n = len - total;
		if (io_stream_read(s, p + total, &n) != 0) {
			return false;
		}
		if (n == 0) {
			return false;
		}
		total += n;
	}
	return !fixture_inject_failure(FIXTURE_FAIL_READ);
}

/* One more read after the payload must be a clean EOF, returning 0 with
 * n == 0: a reader that fails at EOF, or a stream missing its final block,
 * can still deliver every payload byte first. */
static bool stream_at_eof(struct io_stream *restrict s)
{
	unsigned char b;
	size_t n = sizeof(b);
	return io_stream_read(s, &b, &n) == 0 && n == 0;
}

/* Fill a buffer with xorshift32 output, which deflate cannot compress. */
static void fill_random(uint_least8_t *restrict buf, const size_t len)
{
	uint_least32_t x = UINT32_C(2463534242);
	for (size_t i = 0; i < len; ++i) {
		x ^= (x << 13) & UINT32_C(0xffffffff);
		x ^= x >> 17;
		x ^= (x << 5) & UINT32_C(0xffffffff);
		buf[i] = (uint_least8_t)(x & 0xffU);
	}
}

/* A read-only stream over a fixed memory buffer that exposes only .read (no
 * direct_read). Feeding it to codec_zlib_reader/codec_gzip_reader forces their
 * io_bufreader-wrap fallback for a base stream lacking direct_read — the path
 * that io_memreader (which implements direct_read) never triggers. */
struct ro_memstream {
	struct io_stream s;
	const unsigned char *data;
	size_t len;
	size_t pos;
};

static int ro_mem_read(void *p, void *buf, size_t *restrict len)
{
	struct ro_memstream *restrict m = p;
	size_t n = m->len - m->pos;
	if (n > *len) {
		n = *len;
	}
	memcpy(buf, m->data + m->pos, n);
	m->pos += n;
	*len = n;
	return 0;
}

static int ro_mem_close(void *p)
{
	free(p);
	return 0;
}

static struct io_stream *ro_memreader(const void *data, const size_t len)
{
	static const struct io_stream_vftable vftable = {
		.read = ro_mem_read,
		.close = ro_mem_close,
	};
	struct ro_memstream *restrict m = malloc(sizeof(*m));
	if (m == NULL) {
		return NULL;
	}
	m->s = (struct io_stream){ .vftable = &vftable, .data = NULL };
	m->data = data;
	m->len = len;
	m->pos = 0;
	return &m->s;
}

/* A read-only stream that implements direct_read but deliberately returns a
 * short read (at most `chunk` bytes, fewer than requested) on every call while
 * input remains, signalling EOF (n == 0) only once the buffer is exhausted.
 * io/stream.h permits a base stream to short-read without being at EOF, but
 * io_memreader never does; this exercises the codec readers on that contract. */
struct drip_memstream {
	struct io_stream s;
	const unsigned char *data;
	size_t len;
	size_t pos;
	size_t chunk;
};

static int
drip_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct drip_memstream *restrict m = p;
	size_t n = m->len - m->pos;
	if (n > *len) {
		n = *len;
	}
	if (n > m->chunk) {
		n = m->chunk; /* short even when more input remains */
	}
	*buf = m->data + m->pos;
	m->pos += n;
	*len = n;
	return 0;
}

static int drip_mem_close(void *p)
{
	free(p);
	return 0;
}

static struct io_stream *
drip_memreader(const void *data, const size_t len, const size_t chunk)
{
	static const struct io_stream_vftable vftable = {
		.direct_read = drip_direct_read,
		.close = drip_mem_close,
	};
	struct drip_memstream *restrict m = malloc(sizeof(*m));
	if (m == NULL) {
		return NULL;
	}
	m->s = (struct io_stream){ .vftable = &vftable, .data = NULL };
	m->data = data;
	m->len = len;
	m->pos = 0;
	m->chunk = chunk;
	return &m->s;
}

/* A writer that passes its first `ungated` bytes through in full (so the gzip
 * constructor's one-shot 10-byte header write succeeds), then accepts at most
 * `chunk` bytes per call, appending everything to *pvbuf. Exercises the codec
 * writers' resumable partial-write paths (body/finish/trailer) that
 * io_heapwriter -- which always accepts the whole buffer -- never triggers.
 * A nonzero `err` instead fails every nonempty write past the ungated prefix
 * with that code. Tests may retune chunk/err through the returned stream. */
struct choke_memwriter {
	struct io_stream s;
	struct vbuffer **pvbuf;
	size_t ungated;
	size_t chunk;
	size_t written;
	int err;
};

static int choke_write(void *p, const void *restrict buf, size_t *restrict len)
{
	struct choke_memwriter *restrict m = p;
	size_t n = *len;
	if (m->written >= m->ungated && m->err != 0 && n > 0) {
		*len = 0;
		return m->err;
	}
	if (m->written >= m->ungated && n > m->chunk) {
		n = m->chunk; /* short even when more output is offered */
	}
	VBUF_APPEND(*m->pvbuf, buf, n);
	m->written += n;
	*len = n;
	return 0;
}

static int choke_flush(void *p)
{
	(void)p;
	return 0;
}

static int choke_close(void *p)
{
	free(p);
	return 0;
}

static struct io_stream *choke_memwriter(
	struct vbuffer **restrict pvbuf, const size_t ungated,
	const size_t chunk)
{
	static const struct io_stream_vftable vftable = {
		.write = choke_write,
		.flush = choke_flush,
		.close = choke_close,
	};
	struct choke_memwriter *restrict m = malloc(sizeof(*m));
	if (m == NULL) {
		return NULL;
	}
	m->s = (struct io_stream){ .vftable = &vftable, .data = NULL };
	m->pvbuf = pvbuf;
	m->ungated = ungated;
	m->chunk = chunk;
	m->written = 0;
	m->err = 0;
	return &m->s;
}

/* A reader that reports an error alongside its last bytes, or immediately
 * when initialized without data. */
struct err_memstream {
	struct io_stream s;
	const unsigned char *data;
	size_t len, pos;
	int err;
};

static int
err_direct_read(void *p, const void **restrict buf, size_t *restrict len)
{
	struct err_memstream *restrict m = p;
	size_t n = m->len - m->pos;
	if (n > *len) {
		n = *len;
	}
	*buf = n > 0 ? m->data + m->pos : NULL;
	m->pos += n;
	*len = n;
	return m->pos == m->len ? m->err : 0;
}

static int err_mem_close(void *p)
{
	free(p);
	return 0;
}

static struct io_stream *
err_memreader(const int err, const void *data, const size_t len)
{
	static const struct io_stream_vftable vftable = {
		.direct_read = err_direct_read,
		.close = err_mem_close,
	};
	struct err_memstream *restrict m = malloc(sizeof(*m));
	if (m == NULL) {
		return NULL;
	}
	m->s = (struct io_stream){ .vftable = &vftable, .data = NULL };
	m->data = data;
	m->len = len;
	m->pos = 0;
	m->err = err;
	return &m->s;
}

static int write_tempfile(char *restrict tmpl, const void *content, size_t len)
{
	const int fd = mkstemp(tmpl);
	if (fd < 0) {
		return -1;
	}
	if ((size_t)write(fd, content, len) != len) {
		(void)close(fd);
		(void)unlink(tmpl);
		return -1;
	}
	return close(fd);
}

static bool read_lua_source(
	const char *restrict path, char *restrict out, const size_t cap,
	size_t *restrict out_len)
{
	struct io_stream *restrict r = codec_lua_reader(path);
	if (r == NULL) {
		return false;
	}
	size_t total = 0;
	for (;;) {
		size_t n = cap - total;
		if (n == 0 || io_stream_read(r, out + total, &n) != 0) {
			io_stream_close(r);
			return false;
		}
		if (n == 0) {
			break;
		}
		total += n;
	}
	*out_len = total;
	const int err = io_stream_close(r);
	if (fixture_inject_failure(FIXTURE_FAIL_LUA_SOURCE)) {
		memcpy(fixture_failed_path, path, strlen(path) + 1);
		return false;
	}
	return err == 0;
}

struct codec_fixture {
	struct vbuffer *compressed;
	struct vbuffer *plain;
	struct vbuffer *extra;
	struct vbuffer *output_buffer;
	struct io_stream *writer;
	struct io_stream *reader;
	struct io_stream *sink;
	unsigned char *src;
	unsigned char *output;
	unsigned char *bytes;
	char path[sizeof(TEST_TMPDIR "/codec_test_XXXXXX")];
};

static size_t fixture_live;

static int fixture_close(struct io_stream **stream)
{
	struct io_stream *owned = *stream;
	*stream = NULL;
	if (owned == NULL) {
		return 0;
	}
	const int err = io_stream_close(owned);
	return fixture_inject_failure(FIXTURE_FAIL_CLOSE) ? EIO : err;
}

static void fixture_unlink(struct codec_fixture *f)
{
	if (f->path[0] != '\0') {
		(void)unlink(f->path);
		f->path[0] = '\0';
	}
}

static void codec_fixture_cleanup(void *data)
{
	struct codec_fixture *f = data;
	(void)fixture_close(&f->reader);
	(void)fixture_close(&f->writer);
	(void)fixture_close(&f->sink);
	VBUF_FREE(f->compressed);
	VBUF_FREE(f->plain);
	VBUF_FREE(f->extra);
	VBUF_FREE(f->output_buffer);
	free(f->src);
	free(f->output);
	free(f->bytes);
	fixture_unlink(f);
	crc_calls = 0;
	fixture_failure = FIXTURE_FAIL_NONE;
	--fixture_live;
	free(f);
}

static struct codec_fixture *codec_fixture_new(void)
{
	struct codec_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	++fixture_live;
	return f;
}

/*
 * Regression: a real shebang line ("#!/usr/bin/env lua\n") is longer than
 * the reader's old 4-byte BOM-detection peek, so lua_skip_shebang never
 * saw the newline within that window and the raw "#!/u" bytes were
 * emitted as if they were Lua source.
 */
T_DECLARE_CASE(codec_lua_reader_strips_shebang)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] =
		"#!/usr/bin/env lua --with-a-fairly-long-set-of-flags-here\n"
		"return 1\n";
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	fixture_unlink(f);
}

/*
 * Regression: a UTF-8 BOM followed immediately by "#!" leaves only 1 byte
 * of the 4-byte peek for the shebang-prefix check, so lua_skip_shebang
 * used to give up before it could even confirm a shebang was present.
 */
T_DECLARE_CASE(codec_lua_reader_strips_bom_and_shebang)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] = "\xEF\xBB\xBF"
				      "#!/usr/bin/env lua\n"
				      "return 1\n";
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	fixture_unlink(f);
}

T_DECLARE_CASE(codec_lua_reader_strips_bom_only)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] = "\xEF\xBB\xBF"
				      "return 1\n";
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	fixture_unlink(f);
}

/* Regression: the first read (the BOM peek) must not return more bytes than
 * the caller requested; a sub-LUA_PEEK_SIZE first io_stream_read() on a BOM-less
 * file would otherwise over-copy LUA_PEEK_SIZE bytes into the smaller buffer. */
T_DECLARE_CASE(codec_lua_reader_small_first_read)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] = "return 1234\n"; /* no BOM, no shebang */
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	f->reader = codec_lua_reader(f->path);
	T_CHECK(f->reader != NULL);

	/* exact-sized heap buffer (< LUA_PEEK_SIZE) so ASan flags any over-copy */
	enum { SMALL = 4 };
	f->bytes = malloc(SMALL);
	T_CHECK(f->bytes != NULL);
	size_t n = SMALL;
	T_EXPECT_EQ(io_stream_read(f->reader, f->bytes, &n), 0);
	T_EXPECT(n > 0);
	T_EXPECT(
		n <=
		(size_t)SMALL); /* direct_read must not exceed the request */
	T_EXPECT_MEMEQ(f->bytes, content, n);

	free(f->bytes);
	f->bytes = NULL;
	(void)fixture_close(&f->reader);
	fixture_unlink(f);
}

/*
 * codec_lua_reader peeks two bytes and, on the gzip magic, wraps the base in
 * codec_gzip_reader before the BOM/shebang stripper. Every other reader case
 * feeds plaintext, and every other caller uses plaintext/"-"/nonexistent
 * paths, so the documented "auto-detects gzip" feature -- loading a .lua.gz
 * ruleset, including the compound path where the shebang is stripped by
 * reading *through* the decompressor -- was entirely unverified.
 */
T_DECLARE_CASE(codec_lua_reader_gunzips_source)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const char content[] = "#!/usr/bin/env lua\n"
				      "return 1\n";
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	{
		f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(
			f->writer, content, sizeof(content) - 1));
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
	}
	T_CHECK(f->compressed != NULL);
	/* the magic the detector keys on */
	T_CHECK(VBUF_LEN(f->compressed) > 2);
	{
		const unsigned char *const magic = VBUF_DATA(f->compressed);
		T_EXPECT_EQ(magic[0], 0x1f);
		T_EXPECT_EQ(magic[1], 0x8b);
	}

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	T_CHECK(write_tempfile(
			f->path, VBUF_DATA(f->compressed),
			VBUF_LEN(f->compressed)) == 0);
	VBUF_FREE(f->compressed);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	/* decompressed, and the shebang stripped through the decompressor */
	T_EXPECT_EQ(len, strlen("return 1\n"));
	T_EXPECT_MEMEQ(out, "return 1\n", len);

	fixture_unlink(f);
}

T_DECLARE_CASE(codec_lua_reader_passthrough_plain_file)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] = "return 1\n";
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, sizeof(content) - 1);
	T_EXPECT_MEMEQ(out, content, len);

	fixture_unlink(f);
}

/* A file that is nothing but a UTF-8 BOM is a valid (empty) chunk: the BOM is
 * stripped and no source bytes are emitted. Exercises the peek window filling
 * to exactly the BOM length and then hitting EOF. */
T_DECLARE_CASE(codec_lua_reader_bom_only_no_content)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	static const char content[] =
		"\xEF\xBB\xBF"; /* UTF-8 BOM, nothing after */
	T_CHECK(write_tempfile(f->path, content, sizeof(content) - 1) == 0);

	char out[128];
	size_t len = 12345;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, (size_t)0);

	fixture_unlink(f);
}

/* An empty source yields an empty chunk cleanly: a zero-length first read is
 * EOF, not a state the reader must recover from. */
T_DECLARE_CASE(codec_lua_reader_empty_stream)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	T_CHECK(write_tempfile(f->path, "", 0) == 0);

	char out[128];
	size_t len = 12345;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, (size_t)0);

	fixture_unlink(f);
}

/*
 * Regression: a shebang line longer than the peek window whose terminating
 * newline falls exactly on a direct_read chunk boundary (offset == n). The
 * bufreader serves the file in IO_BUFSIZE chunks after the 8-byte peek, so a
 * shebang line of exactly IO_BUFSIZE bytes puts its '\n' as the last byte of
 * the first post-peek chunk. lua_direct_read's continuation loop then flips to
 * LUA_PASSTHROUGH but re-iterates; if it re-runs lua_skip_shebang on the next
 * chunk of real source it strips that chunk's first line. The whole source
 * ("return 42\n" + "return 7\n") must survive.
 */
T_DECLARE_CASE(codec_lua_reader_shebang_newline_on_chunk_boundary)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
	       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
	enum { SHEBANG_LEN = IO_BUFSIZE };
	static const char source[] = "return 42\nreturn 7\n";
	const size_t total = SHEBANG_LEN + sizeof(source) - 1;
	char *const content = malloc(total);
	T_CHECK(content != NULL);
	/* "#!" + filler + '\n', exactly IO_BUFSIZE bytes. */
	content[0] = '#';
	content[1] = '!';
	memset(content + 2, 'x', SHEBANG_LEN - 3);
	content[SHEBANG_LEN - 1] = '\n';
	memcpy(content + SHEBANG_LEN, source, sizeof(source) - 1);
	const int rc = write_tempfile(f->path, content, total);
	free(content);
	T_CHECK(rc == 0);

	/* Read with a buffer larger than IO_BUFSIZE so the first post-peek chunk
	 * spans the whole 4088-byte buffered remainder up to the boundary. */
	char out[2 * IO_BUFSIZE];
	size_t len;
	T_EXPECT(read_lua_source(f->path, out, sizeof(out), &len));
	T_EXPECT_EQ(len, sizeof(source) - 1);
	T_EXPECT_MEMEQ(out, source, len);

	fixture_unlink(f);
}

T_DECLARE_CASE(codec_null_base)
{
	T_EXPECT(codec_zlib_writer(NULL) == NULL);
	T_EXPECT(codec_deflate_writer(NULL) == NULL);
	T_EXPECT(codec_zlib_reader(NULL) == NULL);
	T_EXPECT(codec_inflate_reader(NULL) == NULL);
	T_EXPECT(codec_gzip_writer(NULL) == NULL);
	T_EXPECT(codec_gzip_reader(NULL) == NULL);
}

T_DECLARE_CASE(codec_zlib_roundtrip)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 16384 };
	uint_least8_t src[N];
	uint_least8_t out[N];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 37U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	f->writer = codec_zlib_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N / 3));
	T_EXPECT(stream_write_all(f->writer, src + (N / 3), N - (N / 3)));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL);
	T_EXPECT(VBUF_LEN(f->compressed) > 0);

	f->reader = codec_zlib_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* Feed a base stream lacking direct_read to codec_zlib_reader and
 * codec_gzip_reader, exercising their io_bufreader-wrap fallback. */
T_DECLARE_CASE(codec_reader_wraps_base_without_direct_read)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 4096 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 29U + 11U) & 0xffU);
	}

	struct io_stream *(*const readers[])(struct io_stream *) = {
		codec_zlib_reader,
		codec_gzip_reader,
	};
	struct io_stream *(*const writers[])(struct io_stream *) = {
		codec_zlib_writer,
		codec_gzip_writer,
	};
	for (size_t v = 0; v < ARRAY_SIZE(readers); ++v) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);
		f->writer = writers[v](io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(f->writer, src, N));
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
		T_CHECK(f->compressed != NULL);
		T_EXPECT(VBUF_LEN(f->compressed) > 0);

		struct io_stream *base = ro_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed));
		T_CHECK(base != NULL);
		T_CHECK(base->vftable->direct_read == NULL);
		f->reader = readers[v](base);
		T_CHECK(f->reader != NULL);
		T_EXPECT(stream_read_exact(f->reader, out, N));
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
		T_EXPECT_MEMEQ(out, src, N);
		VBUF_FREE(f->compressed);
	}
}

/* Regression: a base stream that returns short direct_reads (fewer bytes than
 * requested) while more input remains must not make the inflate/gzip readers
 * stop early and report a truncated stream. Before the fix, the first short
 * read set srceof and dropped TINFL_FLAG_HAS_MORE_INPUT, so valid input decoded
 * to a truncation error. */
T_DECLARE_CASE(codec_reader_short_direct_read_is_not_eof)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 8192, CHUNK = 7 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 53U + 7U) & 0xffU);
	}

	struct io_stream *(*const readers[])(struct io_stream *) = {
		codec_zlib_reader,
		codec_gzip_reader,
	};
	struct io_stream *(*const writers[])(struct io_stream *) = {
		codec_zlib_writer,
		codec_gzip_writer,
	};
	for (size_t v = 0; v < ARRAY_SIZE(readers); ++v) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);
		f->writer = writers[v](io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(f->writer, src, N));
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
		T_CHECK(f->compressed != NULL);
		/* incompressible-ish input keeps the stream many chunks long */
		T_EXPECT(VBUF_LEN(f->compressed) > CHUNK);

		struct io_stream *base = drip_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed),
			CHUNK);
		T_CHECK(base != NULL);
		T_CHECK(base->vftable->direct_read != NULL);
		f->reader = readers[v](base);
		T_CHECK(f->reader != NULL);
		T_EXPECT(stream_read_exact(f->reader, out, N));
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
		T_EXPECT_MEMEQ(out, src, N);
		VBUF_FREE(f->compressed);
	}
}

/* Regression guard for the fix above: now that a short read is no longer EOF, a
 * gzip member header truncated mid-way must still be reported as an error when
 * the base later signals EOF on a refill, not silently accepted as a clean
 * end-of-stream. Feeds the truncated-after-FEXTRA input one byte per read. */
T_DECLARE_CASE(codec_gzip_truncated_header_via_short_reads_fails)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const unsigned char trunc[] = {
		/* 10-byte header, FLG = FEXTRA(0x04) | FNAME(0x08) */
		0x1f, 0x8b, 0x08, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		/* XLEN = 4, a 4-byte extra field, then EOF (no name follows) */
		0x04, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
	};
	f->reader = codec_gzip_reader(drip_memreader(trunc, sizeof(trunc), 1));
	T_CHECK(f->reader != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	const int rret = io_stream_read(f->reader, out, &n);
	const int cret = fixture_close(&f->reader);
	T_EXPECT(rret != 0 || cret != 0);
}

T_DECLARE_CASE(codec_deflate_roundtrip)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 8192 };
	uint_least8_t src[N];
	uint_least8_t out[N];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 13U + 17U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	f->writer = codec_deflate_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL);
	T_EXPECT(VBUF_LEN(f->compressed) > 0);

	f->reader = codec_inflate_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

T_DECLARE_CASE(codec_gzip_roundtrip)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 16384 };
	uint_least8_t src[N];
	uint_least8_t out[N];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 53U + 7U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N / 2));
	T_EXPECT(stream_write_all(f->writer, src + (N / 2), N - (N / 2)));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL);
	T_EXPECT(VBUF_LEN(f->compressed) > 0);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/*
 * The decompressors reset their TINFL_LZ_DICT_SIZE (32 KiB) ring only once it
 * is both completely full and completely drained. No other case decompresses
 * more than 16 KiB in one run, so that reset -- and LZ back-references
 * resolving across it, the subtlest correctness point in the module -- never
 * ran, even though it is on the hot path for any HTTP body or gzip ruleset
 * over 32 KiB decompressed. Read back in small chunks so the ring fills and
 * wraps repeatedly.
 */
T_DECLARE_CASE(codec_decompress_ring_wraparound)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 100000 }; /* > TINFL_LZ_DICT_SIZE */
	static const struct {
		const char *name;
		struct io_stream *(*writer)(struct io_stream *);
		struct io_stream *(*reader)(struct io_stream *);
	} variants[] = {
		{ "zlib", codec_zlib_writer, codec_zlib_reader },
		{ "deflate", codec_deflate_writer, codec_inflate_reader },
		{ "gzip", codec_gzip_writer, codec_gzip_reader },
	};
	f->src = malloc(N);
	f->output = malloc(N);
	T_CHECK(f->src != NULL);
	T_CHECK(f->output != NULL);
	/* Moderately compressible: a repeating motif perturbed periodically, so
	 * the encoder emits real back-references (some reaching across the ring
	 * boundary) rather than one long run. */
	for (size_t i = 0; i < (size_t)N; ++i) {
		f->src[i] = (uint_least8_t)((i % 251U) ^ ((i / 1024U) & 0x0fU));
	}

	for (size_t v = 0; v < ARRAY_SIZE(variants); v++) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);

		f->writer = variants[v].writer(io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(f->writer, f->src, N));
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
		T_CHECK(f->compressed != NULL);
		/* it really did compress, so back-references are in play */
		T_EXPECT(VBUF_LEN(f->compressed) < (size_t)N);

		f->reader = variants[v].reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		memset(f->output, 0, N);
		for (size_t off = 0; off < (size_t)N;) {
			size_t n = (size_t)N - off;
			if (n > 1000) {
				n = 1000;
			}
			T_EXPECT(stream_read_exact(
				f->reader, f->output + off, n));
			off += n;
		}
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
		T_EXPECT_MEMEQ(f->output, f->src, N);
		VBUF_FREE(f->compressed);
	}

	free(f->src);
	f->src = NULL;
	free(f->output);
	f->output = NULL;
}

T_DECLARE_CASE(codec_gzip_multiframe)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 4096 };
	uint_least8_t src1[N], src2[N];
	uint_least8_t out[N * 2];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src1[i] = (uint_least8_t)((i * 11U) & 0xffU);
		src2[i] = (uint_least8_t)((i * 17U + 3U) & 0xffU);
	}
	f->plain = VBUF_NEW(64);
	f->extra = VBUF_NEW(64);
	T_CHECK(f->plain != NULL);
	T_CHECK(f->extra != NULL);

	f->writer = codec_gzip_writer(io_heapwriter(&f->plain));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src1, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	f->writer = codec_gzip_writer(io_heapwriter(&f->extra));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src2, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	/* Concatenate both gzip members into one buffer */
	f->compressed = VBUF_NEW(VBUF_LEN(f->plain) + VBUF_LEN(f->extra));
	T_CHECK(f->compressed != NULL);
	VBUF_APPEND(f->compressed, VBUF_DATA(f->plain), VBUF_LEN(f->plain));
	VBUF_APPEND(f->compressed, VBUF_DATA(f->extra), VBUF_LEN(f->extra));
	T_CHECK(!VBUF_HAS_OOM(f->compressed));
	VBUF_FREE(f->plain);
	VBUF_FREE(f->extra);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, (size_t)N * 2));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src1, N);
	T_EXPECT_MEMEQ(out + N, src2, N);
	VBUF_FREE(f->compressed);
}

T_DECLARE_CASE(codec_gzip_crc_error)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 512 };
	uint_least8_t src[N];
	uint_least8_t dummy[N];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 7U + 5U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) >= 8);
	/* Flip a bit in the CRC-32 field (last 8 bytes, first 4 = CRC) */
	((unsigned char *)VBUF_DATA(
		f->compressed))[VBUF_LEN(f->compressed) - 8] ^= 0x01;

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	/* Read all body data, then probe for trailer to trigger validation */
	(void)io_stream_read(f->reader, dummy, &(size_t){ sizeof(dummy) });
	{
		unsigned char probe[1];
		size_t n = sizeof(probe);
		(void)io_stream_read(f->reader, probe, &n);
	}
	const int err = fixture_close(&f->reader);
	VBUF_FREE(f->compressed);
	T_EXPECT(err != 0);
}

T_DECLARE_CASE(codec_gzip_flush_multiframe)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N1 = 4096, N2 = 4096 };
	uint_least8_t src1[N1], src2[N2];
	uint_least8_t out[N1 + N2];

	size_t i = 0;

	for (i = 0; i < N1; ++i) {
		src1[i] = (uint_least8_t)((i * 23U) & 0xffU);
	}
	for (i = 0; i < N2; ++i) {
		src2[i] = (uint_least8_t)((i * 31U + 9U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	/* Write two frames via flush boundary */
	f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src1, N1));
	T_EXPECT_EQ(io_stream_flush(f->writer), 0);
	T_EXPECT(stream_write_all(f->writer, src2, N2));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL);
	T_EXPECT(VBUF_LEN(f->compressed) > 0);

	/* Verify two gzip magic headers in the compressed output */
	{
		const unsigned char *data = VBUF_DATA(f->compressed);
		const size_t len = VBUF_LEN(f->compressed);
		T_EXPECT(len >= 20);
		T_EXPECT(data[0] == 0x1f && data[1] == 0x8b);
		/* Scan for second gzip header after the first member */
		size_t found = 0;
		for (size_t j = 4; j + 1 < len; ++j) {
			if (data[j] == 0x1f && data[j + 1] == 0x8b) {
				found = j;
				break;
			}
		}
		T_EXPECT(found > 0);
	}

	/* Read back with gzip_reader (supports multi-member) */
	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N1 + N2));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src1, N1);
	T_EXPECT_MEMEQ(out + N1, src2, N2);
	VBUF_FREE(f->compressed);
}

T_DECLARE_CASE(codec_gzip_flush_empty)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 4096 };
	uint_least8_t src[N];
	uint_least8_t out[N];

	size_t i = 0;

	for (i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 41U + 13U) & 0xffU);
	}
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);

	/* Flush then close without writing more data should produce one member */
	f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(io_stream_flush(f->writer), 0);
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	T_CHECK(f->compressed != NULL);
	T_EXPECT(VBUF_LEN(f->compressed) > 0);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);

	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* gzip header flag bits (RFC 1952), mirrored from codec.c */
enum {
	GZIP_FHCRC = 1 << 1,
	GZIP_FEXTRA = 1 << 2,
	GZIP_FNAME = 1 << 3,
	GZIP_FCOMMENT = 1 << 4,
};

/* Compress src via the gzip writer and return the raw member bytes. */
static struct vbuffer *gzip_make_member(const void *src, const size_t srclen)
{
	struct vbuffer *compressed = VBUF_NEW(64);
	if (compressed == NULL) {
		return NULL;
	}
	struct io_stream *w = codec_gzip_writer(io_heapwriter(&compressed));
	if (w == NULL) {
		VBUF_FREE(compressed);
		return NULL;
	}
	const bool written = stream_write_all(w, src, srclen);
	const int err = io_stream_close(w);
	if (!written || err != 0) {
		VBUF_FREE(compressed);
		return NULL;
	}
	return compressed;
}

/* The CRC is independent of ISIZE: changing only the final four trailer
 * bytes must be rejected after the unchanged body has been delivered. */
T_DECLARE_CASE(codec_gzip_isize_error)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 200 };
	unsigned char src[N];
	for (size_t i = 0; i < (size_t)N; i++) {
		src[i] = (unsigned char)((i * 7U + 3U) & 0xffU);
	}
	/* Exercise every ISIZE byte, then the unchanged member as a control. */
	for (size_t byte = 0; byte <= 4; byte++) {
		f->compressed = gzip_make_member(src, N);
		T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) > 8);
		const bool corrupt = byte < 4;
		if (corrupt) {
			((unsigned char *)VBUF_DATA(f->compressed))
				[VBUF_LEN(f->compressed) - 4 + byte] ^= 0x01;
		}
		f->reader = codec_gzip_reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		unsigned char out[N];
		T_EXPECT(stream_read_exact(f->reader, out, sizeof(out)));
		T_EXPECT_MEMEQ(out, src, sizeof(src));
		unsigned char probe;
		size_t n = sizeof(probe);
		const int rret = io_stream_read(f->reader, &probe, &n);
		const int cret = fixture_close(&f->reader);
		VBUF_FREE(f->compressed);
		T_EXPECT_EQ(n, 0);
		if (corrupt) {
			T_EXPECT(rret != 0);
			T_EXPECT(cret != 0);
		} else {
			T_EXPECT_EQ(rret, 0);
			T_EXPECT_EQ(cret, 0);
		}
	}
}

/*
 * Build a gzip member that carries the optional FEXTRA, FNAME, FCOMMENT and
 * FHCRC header fields. The miniz writer never emits these, so the reader's
 * optional-field parser is only reachable from hand-crafted input. When
 * corrupt_hcrc is true the stored header CRC-16 is flipped to drive the
 * mismatch path.
 */
static struct vbuffer *
gzip_with_opt_headers(const void *src, const size_t srclen, bool corrupt_hcrc)
{
	struct vbuffer *plain = gzip_make_member(src, srclen);
	if (plain == NULL) {
		return NULL;
	}
	const unsigned char *p = VBUF_DATA(plain);
	const size_t plen = VBUF_LEN(plain);
	if (plen < 10) {
		VBUF_FREE(plain);
		return NULL;
	}

	static const unsigned char extra[] = { 'A', 'B', 'C', 'D' };
	static const unsigned char name[] = { 'n', 'a', 'm', 'e', 0x00 };
	static const unsigned char comment[] = { 'h', 'i', 0x00 };

	struct vbuffer *out = VBUF_NEW(plen + 32);
	if (out == NULL) {
		VBUF_FREE(plain);
		return NULL;
	}
	/* fixed 10-byte header with optional-field flags set */
	unsigned char hdr[10];
	memcpy(hdr, p, sizeof(hdr));
	hdr[3] = GZIP_FEXTRA | GZIP_FNAME | GZIP_FCOMMENT | GZIP_FHCRC;
	VBUF_APPEND(out, hdr, sizeof(hdr));
	/* FEXTRA: 2-byte little-endian length then the extra bytes */
	const unsigned char xlen[2] = { (unsigned char)sizeof(extra), 0x00 };
	VBUF_APPEND(out, xlen, sizeof(xlen));
	VBUF_APPEND(out, extra, sizeof(extra));
	/* FNAME and FCOMMENT: NUL-terminated strings */
	VBUF_APPEND(out, name, sizeof(name));
	VBUF_APPEND(out, comment, sizeof(comment));
	/* FHCRC: low 16 bits of the CRC-32 over all preceding header bytes */
	const mz_ulong crc =
		mz_crc32(MZ_CRC32_INIT, VBUF_DATA(out), VBUF_LEN(out));
	unsigned char hcrc[2] = { (unsigned char)(crc & 0xffu),
				  (unsigned char)((crc >> 8) & 0xffu) };
	if (corrupt_hcrc) {
		hcrc[0] ^= 0xffu;
	}
	VBUF_APPEND(out, hcrc, sizeof(hcrc));
	/* DEFLATE body and trailer copied verbatim from the plain member */
	VBUF_APPEND(out, p + 10, plen - 10);

	const bool ok = !VBUF_HAS_OOM(out);
	VBUF_FREE(plain);
	if (!ok) {
		VBUF_FREE(out);
		return NULL;
	}
	return out;
}

static struct vbuffer *gzip_with_text_headers(
	const struct vbuffer *plain, const unsigned char flags,
	const size_t length)
{
	struct vbuffer *g = VBUF_NEW(VBUF_LEN(plain) + 2 * (length + 1) + 2);
	if (g == NULL) {
		return NULL;
	}
	unsigned char hdr[10];
	memcpy(hdr, VBUF_DATA(plain), sizeof(hdr));
	hdr[3] = flags;
	VBUF_APPEND(g, hdr, sizeof(hdr));
	for (int flag = GZIP_FNAME; flag <= GZIP_FCOMMENT; flag <<= 1) {
		if (flags & flag) {
			for (size_t i = 0; i < length; ++i) {
				VBUF_APPEND(g, "x", 1);
			}
			VBUF_APPEND(g, "", 1);
		}
	}
	if (flags & GZIP_FHCRC) {
		const mz_ulong crc =
			mz_crc32(MZ_CRC32_INIT, VBUF_DATA(g), VBUF_LEN(g));
		const unsigned char bytes[] = { (unsigned char)crc,
						(unsigned char)(crc >> 8) };
		VBUF_APPEND(g, bytes, sizeof(bytes));
	}
	VBUF_APPEND(
		g, (const unsigned char *)VBUF_DATA(plain) + 10,
		VBUF_LEN(plain) - 10);
	if (VBUF_HAS_OOM(g)) {
		VBUF_FREE(g);
		return NULL;
	}
	return g;
}

T_DECLARE_SUBCASE(
	gzip_check_text_headers, struct codec_fixture *f,
	const struct vbuffer *g, const bool hcrc)
{
	static const unsigned char payload[] = "text metadata payload";
	static const size_t chunks[] = { 1, 17, IO_BUFSIZE };
	for (size_t i = 0; i < ARRAY_SIZE(chunks); ++i) {
		f->reader = codec_gzip_reader(
			drip_memreader(VBUF_DATA(g), VBUF_LEN(g), chunks[i]));
		T_CHECK(f->reader != NULL);
		unsigned char out[sizeof(payload)];
		crc_calls = 0;
		T_EXPECT(stream_read_exact(f->reader, out, sizeof(out)));
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_MEMEQ(out, payload, sizeof(out));
		/* Ten fixed-header CRCs, at most two text fields per buffer,
		 * and one payload CRC per buffer. */
		const size_t buffers =
			(VBUF_LEN(g) + chunks[i] - 1) / chunks[i];
		T_EXPECT(crc_calls <= 12 + (hcrc ? 2 * buffers : buffers));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
	}
}

/* Long text fields must be consumed per buffered span, not CRC'd byte by
 * byte. Verify the work bound alongside payload/EOF and FHCRC validation. */
T_DECLARE_CASE(codec_gzip_text_headers_use_buffered_spans)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const unsigned char payload[] = "text metadata payload";
	static const unsigned char flags[] = {
		GZIP_FNAME,
		GZIP_FCOMMENT,
		GZIP_FNAME | GZIP_FCOMMENT,
		GZIP_FNAME | GZIP_FHCRC,
		GZIP_FCOMMENT | GZIP_FHCRC,
		GZIP_FNAME | GZIP_FCOMMENT | GZIP_FHCRC,
	};
	static const size_t lengths[] = { 0, IO_BUFSIZE * 2 + 1 };
	f->plain = gzip_make_member(payload, sizeof(payload));
	T_CHECK(f->plain != NULL);
	for (size_t i = 0; i < ARRAY_SIZE(flags); ++i) {
		for (size_t j = 0; j < ARRAY_SIZE(lengths); ++j) {
			f->compressed = gzip_with_text_headers(
				f->plain, flags[i], lengths[j]);
			T_CHECK(f->compressed != NULL);
			const bool hcrc = (flags[i] & GZIP_FHCRC) != 0;
			T_CALL_SUBCASE(
				gzip_check_text_headers, f, f->compressed,
				hcrc);
			if (lengths[j] != 0) {
				/* EOF before the first text terminator must remain a
				 * truncated-header error after spanning several buffers. */
				f->reader = codec_gzip_reader(drip_memreader(
					VBUF_DATA(f->compressed),
					10 + lengths[j], 17));
				T_CHECK(f->reader != NULL);
				unsigned char out;
				size_t n = 1;
				T_EXPECT(
					io_stream_read(f->reader, &out, &n) !=
					0);
				T_EXPECT_EQ(n, 0U);
				T_EXPECT(fixture_close(&f->reader) != 0);
			}
			if (hcrc) {
				const size_t header_len =
					VBUF_LEN(f->compressed) -
					(VBUF_LEN(f->plain) - 10) - 2;
				((unsigned char *)VBUF_DATA(
					f->compressed))[header_len] ^= 1;
				f->reader = codec_gzip_reader(drip_memreader(
					VBUF_DATA(f->compressed),
					VBUF_LEN(f->compressed), 17));
				T_CHECK(f->reader != NULL);
				unsigned char out;
				size_t n = 1;
				T_EXPECT(
					io_stream_read(f->reader, &out, &n) !=
					0);
				T_EXPECT_EQ(n, 0U);
				T_EXPECT(fixture_close(&f->reader) != 0);
			}
			VBUF_FREE(f->compressed);
		}
	}
	VBUF_FREE(f->plain);
}

T_DECLARE_CASE(codec_gzip_optional_headers)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 2048 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 19U + 7U) & 0xffU);
	}

	f->compressed = gzip_with_opt_headers(src, N, false);
	T_CHECK(f->compressed != NULL);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* Regression: an empty FNAME immediately after FEXTRA. The header parser must
 * read the FNAME terminator from srcbuf, not the stale once-per-iteration byte
 * (the nonzero OS byte) carried through the FEXTRA fallthrough. */
T_DECLARE_CASE(codec_gzip_empty_fname_after_fextra)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 2048 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 23U + 5U) & 0xffU);
	}

	f->plain = gzip_make_member(src, N);
	T_CHECK(f->plain != NULL);
	const unsigned char *p = VBUF_DATA(f->plain);
	const size_t plen = VBUF_LEN(f->plain);
	T_CHECK(plen >= 10);

	static const unsigned char extra[] = { 'A', 'B', 'C', 'D' };
	f->compressed = VBUF_NEW(plen + 8);
	T_CHECK(f->compressed != NULL);
	unsigned char hdr[10];
	memcpy(hdr, p, sizeof(hdr));
	hdr[3] = GZIP_FEXTRA | GZIP_FNAME;
	hdr[9] = 0xff; /* OS byte: the (nonzero) stale byte reached at FNAME */
	VBUF_APPEND(f->compressed, hdr, sizeof(hdr));
	const unsigned char xlen[2] = { (unsigned char)sizeof(extra), 0x00 };
	VBUF_APPEND(f->compressed, xlen, sizeof(xlen));
	VBUF_APPEND(f->compressed, extra, sizeof(extra));
	static const unsigned char empty_name[] = { 0x00 }; /* empty FNAME */
	VBUF_APPEND(f->compressed, empty_name, sizeof(empty_name));
	VBUF_APPEND(
		f->compressed, p + 10, plen - 10); /* deflate body + trailer */
	T_CHECK(!VBUF_HAS_OOM(f->compressed));
	VBUF_FREE(f->plain);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* Regression: RFC 1952 requires the reserved FLG bits (0xe0) to be zero. A
 * member with any of bits 5-7 set must be rejected, not decompressed as if the
 * header were valid. The miniz writer emits FLG=0, so each reserved bit is set
 * on an otherwise valid member by hand and must drive a read/close error. */
T_DECLARE_CASE(codec_gzip_rejects_reserved_flag_bits)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 256 };
	uint_least8_t src[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 31U + 3U) & 0xffU);
	}

	static const unsigned char reserved[] = { 0x20, 0x40, 0x80 };
	for (size_t k = 0; k < ARRAY_SIZE(reserved); ++k) {
		f->compressed = gzip_make_member(src, N);
		T_CHECK(f->compressed != NULL);
		T_CHECK(VBUF_LEN(f->compressed) >= 10);
		/* set one reserved FLG bit on the otherwise valid member */
		((unsigned char *)VBUF_DATA(f->compressed))[3] |= reserved[k];

		f->reader = codec_gzip_reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		unsigned char out[N];
		size_t n = sizeof(out);
		const int rret = io_stream_read(f->reader, out, &n);
		const int cret = fixture_close(&f->reader);
		T_EXPECT(rret != 0 || cret != 0);
		VBUF_FREE(f->compressed);
	}
}

/* Regression: a full flush on a zlib/deflate writer must complete instead of
 * looping forever (TDEFL_FULL_FLUSH never reaches TDEFL_STATUS_DONE), and the
 * stream must still decode correctly after the flush and subsequent writes. */
T_DECLARE_CASE(codec_zlib_flush_then_continue)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 4096 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 37U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_zlib_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N / 2));
	T_EXPECT_EQ(io_stream_flush(f->writer), 0);
	T_CHECK(f->compressed != NULL);
	/* the sync point makes everything written so far decodable */
	{
		f->reader = codec_zlib_reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		T_EXPECT(stream_read_exact(f->reader, out, N / 2));
		T_EXPECT_MEMEQ(out, src, N / 2);
		(void)fixture_close(&f->reader);
	}
	T_EXPECT(stream_write_all(f->writer, src + (N / 2), N - (N / 2)));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	f->reader = codec_zlib_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* Corrupt-input coverage for the zlib reader (parallel to the gzip cases): an
 * invalid zlib header and a truncated stream must both fail the read. */
T_DECLARE_CASE(codec_zlib_corrupt_input_fails)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_zlib_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) >= 10);

	/* corrupt the zlib header (byte 0 holds CMF) */
	{
		unsigned char *d = VBUF_DATA(f->compressed);
		const unsigned char saved = d[0];
		d[0] ^= 0xffu;
		f->reader = codec_zlib_reader(
			io_memreader(d, VBUF_LEN(f->compressed)));
		if (f->reader != NULL) {
			T_EXPECT(!stream_read_exact(f->reader, out, N));
			(void)fixture_close(&f->reader);
		}
		d[0] = saved;
	}
	/* truncated stream: only the first few bytes */
	{
		f->reader = codec_zlib_reader(
			io_memreader(VBUF_DATA(f->compressed), 5));
		if (f->reader != NULL) {
			T_EXPECT(!stream_read_exact(f->reader, out, N));
			(void)fixture_close(&f->reader);
		}
	}
	VBUF_FREE(f->compressed);
}

/* codec_zlib_reader validates the trailing adler-32 (miniz enforces it via
 * TINFL_FLAG_PARSE_ZLIB_HEADER); flipping it must make the read/close fail. */
T_DECLARE_CASE(codec_zlib_adler32_mismatch)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_zlib_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) >= 6);

	/* the adler-32 is the last 4 bytes; flip one so it no longer matches */
	unsigned char *d = VBUF_DATA(f->compressed);
	const size_t len = VBUF_LEN(f->compressed);
	d[len - 1] ^= 0xffu;
	f->reader = codec_zlib_reader(io_memreader(d, len));
	T_CHECK(f->reader != NULL);
	/* Read to EOF: the mismatch is reported once all output is consumed
	 * and the trailer is validated, as a real consumer draining the stream
	 * would observe. */
	bool read_failed = false;
	for (;;) {
		size_t n = sizeof(out);
		const int rret = io_stream_read(f->reader, out, &n);
		if (rret != 0) {
			read_failed = true;
			break;
		}
		if (n == 0) {
			break;
		}
	}
	const int cret = fixture_close(&f->reader);
	T_EXPECT(read_failed || cret != 0);
	VBUF_FREE(f->compressed);
}

/* A caller that reads exactly the decompressed length and then closes (without
 * a trailing EOF read) must still see a corrupt adler-32: inflate_close()
 * surfaces the decode status, mirroring the gzip reader. */
T_DECLARE_CASE(codec_zlib_adler32_mismatch_surfaced_at_close)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 1024 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 11U + 3U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_zlib_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) >= 6);

	unsigned char *d = VBUF_DATA(f->compressed);
	const size_t len = VBUF_LEN(f->compressed);
	d[len - 1] ^= 0xffu;
	f->reader = codec_zlib_reader(io_memreader(d, len));
	T_CHECK(f->reader != NULL);
	/* read exactly the decompressed length, then close without a final read */
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(fixture_close(&f->reader) != 0);
	VBUF_FREE(f->compressed);
}

T_DECLARE_CASE(codec_gzip_hcrc_mismatch)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 256 };
	uint_least8_t src[N];
	uint_least8_t out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 29U + 3U) & 0xffU);
	}

	f->compressed = gzip_with_opt_headers(src, N, true);
	T_CHECK(f->compressed != NULL);

	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	/* The corrupt header CRC must make the read fail. */
	size_t n = sizeof(out);
	const int rret = io_stream_read(f->reader, out, &n);
	const int cret = fixture_close(&f->reader);
	T_EXPECT(rret != 0 || cret != 0);
	VBUF_FREE(f->compressed);
}

T_DECLARE_CASE(codec_gzip_read_errors_are_terminal)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const unsigned char payload[] = "gzip error lifetime";
	enum {
		BAD_MAGIC,
		BAD_METHOD,
		RESERVED_FLAG,
		BAD_HCRC,
		SHORT_HEADER,
		BAD_BODY,
		SHORT_BODY,
		SHORT_TRAILER,
		BAD_CRC,
		BAD_ISIZE,
		NUM_ERRORS,
	};
	for (size_t variant = 0; variant < NUM_ERRORS; ++variant) {
		f->compressed =
			variant == BAD_HCRC ?
				gzip_with_opt_headers(
					payload, sizeof(payload), true) :
				gzip_make_member(payload, sizeof(payload));
		T_CHECK(f->compressed != NULL);
		size_t len = VBUF_LEN(f->compressed);
		T_CHECK(len > 18);
		unsigned char *bytes = VBUF_DATA(f->compressed);
		switch (variant) {
		case BAD_MAGIC:
			bytes[0] = 0;
			break;
		case BAD_METHOD:
			bytes[2] = 0;
			break;
		case RESERVED_FLAG:
			bytes[3] = 0x20;
			break;
		case SHORT_HEADER:
			len = 5;
			break;
		case BAD_BODY:
			bytes[10] = 0x07; /* Reserved DEFLATE block type. */
			break;
		case SHORT_BODY:
			len = 10;
			break;
		case SHORT_TRAILER:
			--len;
			break;
		case BAD_CRC:
			bytes[len - 8] ^= 1;
			break;
		case BAD_ISIZE:
			bytes[len - 4] ^= 1;
			break;
		default:
			break;
		}
		f->reader = codec_gzip_reader(io_memreader(bytes, len));
		T_CHECK(f->reader != NULL);
		int err = 0;
		size_t total = 0;
		for (size_t read = 0; read < sizeof(payload) + 1; ++read) {
			const void *out;
			size_t n = sizeof(payload);
			err = io_stream_direct_read(f->reader, &out, &n);
			if (err != 0) {
				T_EXPECT_EQ(n, 0);
				break;
			}
			T_EXPECT(n > 0 && n <= sizeof(payload) - total);
			T_EXPECT_MEMEQ(out, payload + total, n);
			total += n;
		}
		T_EXPECT(err != 0);
		T_EXPECT_EQ(
			total, variant >= SHORT_TRAILER ? sizeof(payload) : 0);
		const size_t calls = crc_calls;
		for (size_t retry = 0; retry < 3; ++retry) {
			const void *out;
			size_t n = sizeof(payload);
			T_EXPECT_EQ(
				io_stream_direct_read(f->reader, &out, &n),
				err);
			T_EXPECT_EQ(n, 0);
		}
		unsigned char out;
		size_t n = sizeof(out);
		T_EXPECT_EQ(io_stream_read(f->reader, &out, &n), err);
		T_EXPECT_EQ(n, 0);
		T_EXPECT_EQ(crc_calls, calls);
		T_EXPECT_EQ(fixture_close(&f->reader), err);
		VBUF_FREE(f->compressed);
	}
}

T_DECLARE_CASE(codec_gzip_bad_magic)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	/* A 10-byte header with an invalid magic must be rejected. */
	static const unsigned char bad[] = {
		0x1f, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	};
	f->reader = codec_gzip_reader(io_memreader(bad, sizeof(bad)));
	T_CHECK(f->reader != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	const int rret = io_stream_read(f->reader, out, &n);
	const int cret = fixture_close(&f->reader);
	T_EXPECT(rret != 0 || cret != 0);
}

/* Regression: a gzip header whose FEXTRA field ends exactly at end-of-input
 * with the FNAME flag set must not read past the source buffer. The FEXTRA_2
 * phase falls through to FNAME without re-checking the loop's srclen guard;
 * before the fix this over-read *srcbuf and underflowed srclen. The exact-size
 * heap buffer lets ASan catch any over-read. */
T_DECLARE_CASE(codec_gzip_truncated_after_fextra)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const unsigned char trunc[] = {
		/* 10-byte header, FLG = FEXTRA(0x04) | FNAME(0x08) */
		0x1f,
		0x8b,
		0x08,
		0x0c,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x03,
		/* XLEN = 4, a 4-byte extra field, then EOF (no name follows) */
		0x04,
		0x00,
		0xaa,
		0xbb,
		0xcc,
		0xdd,
	};
	f->bytes = malloc(sizeof(trunc));
	T_CHECK(f->bytes != NULL);
	memcpy(f->bytes, trunc, sizeof(trunc));
	f->reader = codec_gzip_reader(io_memreader(f->bytes, sizeof(trunc)));
	T_CHECK(f->reader != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	const int rret = io_stream_read(f->reader, out, &n);
	const int cret = fixture_close(&f->reader);
	T_EXPECT(rret != 0 || cret != 0);
	free(f->bytes);
	f->bytes = NULL;
}

/*
 * gzip_decompress_body's mid-stream-EOF path (srceof while the inflate still
 * needs input) fires only when a full IO_BUFSIZE chunk is consumed with more
 * expected (HAS_MORE_INPUT set -> NEEDS_MORE_INPUT) and the next read then hits
 * EOF. Use incompressible data so the deflate body spans more than one chunk,
 * and truncate the member at exactly IO_BUFSIZE.
 */
T_DECLARE_CASE(codec_gzip_truncated_body_fails)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 2 * IO_BUFSIZE };
	unsigned char src[N];
	uint_least32_t rng = 0x9e3779b9u;
	for (size_t i = 0; i < (size_t)N; i++) {
		rng ^= rng << 13;
		rng ^= rng >> 17;
		rng ^= rng << 5;
		src[i] = (unsigned char)(rng & 0xffU);
	}
	f->compressed = gzip_make_member(src, N);
	T_CHECK(f->compressed != NULL);
	/* incompressible data: the body must exceed one IO_BUFSIZE chunk so the
	 * truncation lands mid-body */
	T_CHECK(VBUF_LEN(f->compressed) > (size_t)IO_BUFSIZE);

	f->reader = codec_gzip_reader(
		io_memreader(VBUF_DATA(f->compressed), IO_BUFSIZE));
	T_CHECK(f->reader != NULL);
	unsigned char out[N];
	/* the truncated deflate stream cannot yield all N bytes */
	T_EXPECT(!stream_read_exact(f->reader, out, N));
	(void)fixture_close(&f->reader);
	VBUF_FREE(f->compressed);
}

/*
 * gzip_validate_trailer's short-trailer path: the deflate body is intact but
 * the trailing 8-byte CRC/ISIZE trailer is cut, so the reader must fail when it
 * reaches trailer validation past the body.
 */
T_DECLARE_CASE(codec_gzip_short_trailer_fails)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 200 };
	unsigned char src[N];
	for (size_t i = 0; i < (size_t)N; i++) {
		src[i] = (unsigned char)((i * 7U + 3U) & 0xffU);
	}
	f->compressed = gzip_make_member(src, N);
	T_CHECK(f->compressed != NULL);
	const size_t full = VBUF_LEN(f->compressed);
	T_CHECK(full > 8);

	/* drop 3 of the 8 trailer bytes: header and body intact, trailer short */
	f->reader = codec_gzip_reader(
		io_memreader(VBUF_DATA(f->compressed), full - 3));
	T_CHECK(f->reader != NULL);
	unsigned char out[64];
	int rret = 0;
	for (;;) {
		size_t n = sizeof(out);
		rret = io_stream_read(f->reader, out, &n);
		if (rret != 0 || n == 0) {
			break;
		}
	}
	const int cret = fixture_close(&f->reader);
	/* the N body bytes decode; the short trailer surfaces as an error */
	T_EXPECT(rret != 0 || cret != 0);
	VBUF_FREE(f->compressed);
}

/* -------------------------------------------------------------------------
 * bench - compress + decompress round-trip throughput (per message). Benches
 * run only when a name filter selects them (e.g. --run bench); a plain ctest
 * run skips them.
 * ---------------------------------------------------------------------- */

/* Fill a buffer with moderately compressible data. */
static void bench_fill(uint_least8_t *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		buf[i] = (uint_least8_t)(((i * 37U) ^ (i >> 3)) & 0x3fU);
	}
}

T_DECLARE_BENCH(bench_zlib_roundtrip)
{
	enum { N = 16384 };
	static uint_least8_t src[N];
	uint_least8_t out[N];
	bench_fill(src, N);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		struct vbuffer *compressed = VBUF_NEW(64);
		T_CHECK(compressed != NULL);
		struct io_stream *w =
			codec_zlib_writer(io_heapwriter(&compressed));
		T_CHECK(w != NULL);
		T_CHECK(stream_write_all(w, src, N));
		T_CHECK(io_stream_close(w) == 0);
		struct io_stream *r = codec_zlib_reader(io_memreader(
			VBUF_DATA(compressed), VBUF_LEN(compressed)));
		T_CHECK(r != NULL);
		T_CHECK(stream_read_exact(r, out, N));
		T_CHECK(io_stream_close(r) == 0);
		VBUF_FREE(compressed);
	}
}

T_DECLARE_BENCH(bench_gzip_roundtrip)
{
	enum { N = 16384 };
	static uint_least8_t src[N];
	uint_least8_t out[N];
	bench_fill(src, N);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		struct vbuffer *compressed = VBUF_NEW(64);
		T_CHECK(compressed != NULL);
		struct io_stream *w =
			codec_gzip_writer(io_heapwriter(&compressed));
		T_CHECK(w != NULL);
		T_CHECK(stream_write_all(w, src, N));
		T_CHECK(io_stream_close(w) == 0);
		struct io_stream *r = codec_gzip_reader(io_memreader(
			VBUF_DATA(compressed), VBUF_LEN(compressed)));
		T_CHECK(r != NULL);
		T_CHECK(stream_read_exact(r, out, N));
		T_CHECK(io_stream_close(r) == 0);
		VBUF_FREE(compressed);
	}
}

/* Each of the four unsupported BOMs (UTF-16/32 BE/LE) must be rejected with an
 * error rather than served as Lua source, and the rejection must be sticky: a
 * second read may neither hand out the rejected prefix nor refill and re-run
 * BOM detection from mid-file. */
T_DECLARE_CASE(codec_lua_reader_rejects_unsupported_boms)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	static const struct {
		const char *name;
		unsigned char bom[4];
		size_t len;
	} cases[] = {
		{ "UTF-32 BE", { 0x00, 0x00, 0xFE, 0xFF }, 4 },
		{ "UTF-32 LE", { 0xFF, 0xFE, 0x00, 0x00 }, 4 },
		{ "UTF-16 BE", { 0xFE, 0xFF }, 2 },
		{ "UTF-16 LE", { 0xFF, 0xFE }, 2 },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		memcpy(f->path, TEST_TMPDIR "/codec_test_XXXXXX",
		       sizeof(TEST_TMPDIR "/codec_test_XXXXXX"));
		unsigned char content[16];
		memcpy(content, cases[i].bom, cases[i].len);
		memcpy(content + cases[i].len, "print(1)\n", 9);
		T_CHECK(write_tempfile(f->path, content, cases[i].len + 9) ==
			0);

		f->reader = codec_lua_reader(f->path);
		T_CHECK(f->reader != NULL);
		unsigned char buf[32];
		size_t n = sizeof(buf);
		/* the BOM is rejected with an error, not served */
		T_EXPECT(io_stream_read(f->reader, buf, &n) != 0);
		/* the error is sticky on the next read */
		n = sizeof(buf);
		T_EXPECT(io_stream_read(f->reader, buf, &n) != 0);
		(void)fixture_close(&f->reader);
		fixture_unlink(f);
	}
}

/* A gzip member carrying optional header fields (FEXTRA/FNAME/FCOMMENT/FHCRC)
 * must decode when delivered in tiny refills that split those fields across
 * reads -- exercising header-parse resumption on a successful decode, not only
 * on the truncation paths. */
T_DECLARE_CASE(codec_gzip_optional_headers_across_refills)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 2048 };
	uint_least8_t src[N], out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 29U + 3U) & 0xffU);
	}
	f->compressed = gzip_with_opt_headers(src, N, false);
	T_CHECK(f->compressed != NULL);
	f->reader = codec_gzip_reader(drip_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed), 3));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* codec_inflate_reader (raw DEFLATE, no header/checksum) must not silently
 * accept a corrupted or truncated stream. */
T_DECLARE_CASE(codec_inflate_corrupt_and_truncated_fails)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 1024 };
	uint_least8_t src[N], out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 13U + 7U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_deflate_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, src, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) >= 8);

	/* corrupting a mid-stream byte must not decode back to the original */
	{
		unsigned char *d = VBUF_DATA(f->compressed);
		const size_t mid = VBUF_LEN(f->compressed) / 2;
		const unsigned char saved = d[mid];
		d[mid] ^= 0xffu;
		f->reader = codec_inflate_reader(
			io_memreader(d, VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		const bool ok = stream_read_exact(f->reader, out, N);
		(void)fixture_close(&f->reader);
		T_EXPECT(!ok || memcmp(out, src, N) != 0);
		d[mid] = saved;
	}
	/* a truncated stream must fail rather than yield a short body */
	{
		f->reader = codec_inflate_reader(
			io_memreader(VBUF_DATA(f->compressed), 4));
		T_CHECK(f->reader != NULL);
		T_EXPECT(!stream_read_exact(f->reader, out, N));
		(void)fixture_close(&f->reader);
	}
	VBUF_FREE(f->compressed);
}

/* Regression: the gzip member-finish path must be resumable across a base that
 * short-writes. Once tdefl returns DONE a retried finish must neither re-enter
 * tdefl (which then returns TDEFL_STATUS_BAD_PARAM forever) nor rewrite the
 * trailer prefix; the resumed flush yields one valid member. */
T_DECLARE_CASE(codec_gzip_finish_resumes_after_short_write)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 512 };
	uint_least8_t src[N], out[N];
	for (size_t i = 0; i < N; ++i) {
		src[i] = (uint_least8_t)((i * 17U + 5U) & 0xffU);
	}

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	/* ungated 10 lets the constructor's header write through; 1 byte per
	 * call thereafter forces the body/finish/trailer to drain a byte at a
	 * time so the resumable paths are exercised end to end */
	f->writer = codec_gzip_writer(choke_memwriter(&f->compressed, 10, 1));
	T_CHECK(f->writer != NULL);

	/* write the source, retrying on the -1 backpressure return */
	size_t total = 0;
	int guard = 0;
	while (total < N && guard++ < 1000000) {
		size_t n = N - total;
		const int err = io_stream_write(f->writer, src + total, &n);
		total += n;
		T_CHECK(err == 0 || err == -1);
	}
	T_EXPECT_EQ(total, (size_t)N);

	/* flush finishes the member; retry until the resumable finish completes */
	int ret;
	guard = 0;
	do {
		ret = io_stream_flush(f->writer);
		T_CHECK(ret == 0 || ret == -1);
	} while (ret == -1 && guard++ < 1000000);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(fixture_close(&f->writer), 0);

	/* the produced member must decode back to the source */
	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	T_EXPECT(stream_read_exact(f->reader, out, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(out, src, N);
	VBUF_FREE(f->compressed);
}

/* An immediate base error (no data) must surface as that error code, not the
 * inflate reader's own TINFL_STATUS_NEEDS_MORE_INPUT. */
T_DECLARE_CASE(codec_inflate_surfaces_base_error)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { SENTINEL = -5 };
	f->reader = codec_inflate_reader(err_memreader(SENTINEL, NULL, 0));
	T_CHECK(f->reader != NULL);
	unsigned char out[16];
	size_t n = sizeof(out);
	T_EXPECT_EQ(io_stream_read(f->reader, out, &n), (int)SENTINEL);
	(void)fixture_close(&f->reader);
}

/* A payload that decompresses past CODEC_MAX_INFLATE (overridden to a small
 * value for this test target) must abort with a decode error rather than
 * producing it all -- the decompression-bomb guard. A tiny compressed run of
 * zeros expands past the cap, and the streaming copy must fail before
 * delivering the whole payload. Exercised for both the zlib and gzip
 * streams. */
T_DECLARE_CASE(codec_reader_aborts_decompression_bomb)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	struct io_stream *(*const writers[])(struct io_stream *) = {
		codec_zlib_writer,
		codec_gzip_writer,
	};
	struct io_stream *(*const readers[])(struct io_stream *) = {
		codec_zlib_reader,
		codec_gzip_reader,
	};
	static const unsigned char zeros[IO_BUFSIZE] = { 0 };
	const size_t target = (size_t)CODEC_MAX_INFLATE + sizeof(zeros);

	for (size_t v = 0; v < ARRAY_SIZE(writers); ++v) {
		f->compressed = VBUF_NEW(256);
		T_CHECK(f->compressed != NULL);
		f->writer = writers[v](io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		for (size_t off = 0; off < target; off += sizeof(zeros)) {
			T_CHECK(stream_write_all(
				f->writer, zeros, sizeof(zeros)));
		}
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
		/* the bomb is tiny on the wire */
		T_EXPECT(VBUF_LEN(f->compressed) < target);

		f->reader = readers[v](io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		f->output_buffer = VBUF_NEW(IO_BUFSIZE);
		T_CHECK(f->output_buffer != NULL);
		f->sink = io_heapwriter(&f->output_buffer);
		T_CHECK(f->sink != NULL);
		unsigned char buf[IO_BUFSIZE];
		/* the reader aborts once its cumulative output crosses the cap,
		 * so the copy fails and not all of `target` is delivered */
		T_EXPECT(
			io_stream_copy(f->sink, f->reader, buf, sizeof(buf)) !=
			0);
		T_EXPECT(VBUF_LEN(f->output_buffer) < target);
		(void)fixture_close(&f->sink);
		(void)fixture_close(&f->reader);
		VBUF_FREE(f->output_buffer);
		VBUF_FREE(f->compressed);
	}
}

struct gzip_limit_fixture {
	struct vbuffer *compressed;
	struct io_stream *writer;
	struct io_stream *reader;
};

static void gzip_limit_cleanup(void *data)
{
	struct gzip_limit_fixture *f = data;
	if (f->writer != NULL) {
		(void)io_stream_close(f->writer);
	}
	if (f->reader != NULL) {
		(void)io_stream_close(f->reader);
	}
	VBUF_FREE(f->compressed);
	free(f);
}

T_DECLARE_SUBCASE(expect_gzip_cumulative_limit, const size_t extra)
{
	static const unsigned char zeros[IO_BUFSIZE] = { 0 };
	const size_t first = (size_t)CODEC_MAX_INFLATE / 2;
	const size_t sizes[] = {
		first,
		(size_t)CODEC_MAX_INFLATE - first + extra,
	};
	const size_t target = (size_t)CODEC_MAX_INFLATE + extra;
	struct gzip_limit_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	T_CLEANUP(gzip_limit_cleanup, f);
	f->compressed = VBUF_NEW(256);
	T_CHECK(f->compressed != NULL);
	for (size_t i = 0; i < ARRAY_SIZE(sizes); ++i) {
		T_CHECK(sizes[i] < (size_t)CODEC_MAX_INFLATE);
		f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		for (size_t off = 0; off < sizes[i];) {
			const size_t left = sizes[i] - off;
			const size_t n =
				left < sizeof(zeros) ? left : sizeof(zeros);
			T_CHECK(stream_write_all(f->writer, zeros, n));
			off += n;
		}
		const int err = io_stream_close(f->writer);
		f->writer = NULL;
		T_EXPECT_EQ(err, 0);
	}
	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);

	unsigned char buf[IO_BUFSIZE];
	size_t total = 0;
	int err = 0;
	while (total <= target) {
		size_t n = sizeof(buf);
		err = io_stream_read(f->reader, buf, &n);
		if (err != 0 || n == 0) {
			T_EXPECT_EQ(n, (size_t)0);
			break;
		}
		T_EXPECT(n <= target - total);
		T_EXPECT_MEMEQ(buf, zeros, n);
		total += n;
	}
	if (extra == 0) {
		T_EXPECT_EQ(err, 0);
		T_EXPECT_EQ(total, target);
		T_EXPECT(stream_at_eof(f->reader));
	} else {
		T_EXPECT(err != 0);
		T_EXPECT(total >= first);
		T_EXPECT(total <= (size_t)CODEC_MAX_INFLATE);
	}
}

T_DECLARE_CASE(codec_gzip_accepts_cumulative_limit)
{
	T_CALL_SUBCASE(expect_gzip_cumulative_limit, 0);
}

T_DECLARE_CASE(codec_gzip_rejects_cumulative_limit_plus_one)
{
	T_CALL_SUBCASE(expect_gzip_cumulative_limit, 1);
}

static const struct {
	const char *name;
	struct io_stream *(*writer)(struct io_stream *);
	struct io_stream *(*reader)(struct io_stream *);
} deflate_variants[] = {
	{ "zlib", codec_zlib_writer, codec_zlib_reader },
	{ "deflate", codec_deflate_writer, codec_inflate_reader },
};

/* Regression: incompressible input of ~31 KiB crosses miniz's block threshold
 * while the finish processes the last lookahead, and the resulting block is
 * larger than the writer's output buffer. The calls that drain it return
 * short without having emitted the final block, so the finish (and a full
 * flush) must not stop on a short return that followed a full one. */
T_DECLARE_CASE(codec_deflate_writer_emits_final_block)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 31799, CHUNK = 4096 };
	static const size_t sizes[] = { 31745, 31760, 31799 };
	f->src = malloc(N);
	f->output = malloc(N);
	T_CHECK(f->src != NULL);
	T_CHECK(f->output != NULL);
	fill_random(f->src, N);

	for (size_t v = 0; v < ARRAY_SIZE(deflate_variants); ++v) {
		for (size_t k = 0; k < ARRAY_SIZE(sizes); ++k) {
			const size_t len = sizes[k];
			f->compressed = VBUF_NEW(64);
			T_CHECK(f->compressed != NULL);
			f->writer = deflate_variants[v].writer(
				io_heapwriter(&f->compressed));
			T_CHECK(f->writer != NULL);
			for (size_t off = 0; off < len; off += CHUNK) {
				const size_t n =
					len - off < CHUNK ? len - off : CHUNK;
				T_EXPECT(stream_write_all(
					f->writer, f->src + off, n));
			}
			T_EXPECT_EQ(io_stream_flush(f->writer), 0);
			T_CHECK(f->compressed != NULL);
			/* the flushed prefix alone decodes to all input */
			{
				f->reader =
					deflate_variants[v].reader(io_memreader(
						VBUF_DATA(f->compressed),
						VBUF_LEN(f->compressed)));
				T_CHECK(f->reader != NULL);
				memset(f->output, 0, len);
				T_EXPECT(stream_read_exact(
					f->reader, f->output, len));
				T_EXPECT_MEMEQ(f->output, f->src, len);
				(void)fixture_close(&f->reader);
			}
			T_EXPECT_EQ(fixture_close(&f->writer), 0);

			f->reader = deflate_variants[v].reader(io_memreader(
				VBUF_DATA(f->compressed),
				VBUF_LEN(f->compressed)));
			T_CHECK(f->reader != NULL);
			memset(f->output, 0, len);
			T_EXPECT(stream_read_exact(f->reader, f->output, len));
			T_EXPECT(stream_at_eof(f->reader));
			T_EXPECT_EQ(fixture_close(&f->reader), 0);
			T_EXPECT_MEMEQ(f->output, f->src, len);
			VBUF_FREE(f->compressed);
		}
	}
	free(f->src);
	f->src = NULL;
	free(f->output);
	f->output = NULL;
}

/* The same finish without a preceding flush: the whole stream must end in a
 * final block, not stop inside the last drained block. */
T_DECLARE_CASE(codec_deflate_writer_close_emits_final_block)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 31760 };
	f->src = malloc(N);
	f->output = malloc(N);
	T_CHECK(f->src != NULL);
	T_CHECK(f->output != NULL);
	fill_random(f->src, N);

	for (size_t v = 0; v < ARRAY_SIZE(deflate_variants); ++v) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);
		f->writer = deflate_variants[v].writer(
			io_heapwriter(&f->compressed));
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(f->writer, f->src, N));
		T_EXPECT_EQ(fixture_close(&f->writer), 0);
		T_CHECK(f->compressed != NULL);

		f->reader = deflate_variants[v].reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		T_EXPECT(stream_read_exact(f->reader, f->output, N));
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
		T_EXPECT_MEMEQ(f->output, f->src, N);
		VBUF_FREE(f->compressed);
	}
	free(f->src);
	f->src = NULL;
	free(f->output);
	f->output = NULL;
}

/* Regression: the inflater may report more pending output after the last
 * input byte was consumed (a match running past the end of the 32 KiB ring).
 * A raw DEFLATE stream has no trailer after it, so the reader must keep
 * draining the decompressor at EOF instead of failing at the ring boundary. */
T_DECLARE_CASE(codec_inflate_drains_output_after_input_ends)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 32785 };
	static const uint_least8_t zeros[N] = { 0 };
	f->output = malloc(N);
	T_CHECK(f->output != NULL);

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_deflate_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, zeros, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL);

	f->reader = codec_inflate_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);
	memset(f->output, 0xff, N);
	T_EXPECT(stream_read_exact(f->reader, f->output, N));
	T_EXPECT(stream_at_eof(f->reader));
	T_EXPECT_EQ(fixture_close(&f->reader), 0);
	T_EXPECT_MEMEQ(f->output, zeros, N);
	VBUF_FREE(f->compressed);
	free(f->output);
	f->output = NULL;
}

/* A base can return the last compressed bytes together with an error. The
 * caller stops on that error, so it must follow every pending output byte,
 * including a match that continues after the decompressor wraps its ring. */
T_DECLARE_SUBCASE(
	expect_inflate_drains_before_base_error, const size_t variant,
	const size_t chunk)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 32785 };
	static const unsigned char zeros[N] = { 0 };
	f->output = malloc(N);
	T_CHECK(f->output != NULL);
	memset(f->output, 0xff, N);
	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer =
		deflate_variants[variant].writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_CHECK(stream_write_all(f->writer, zeros, N));
	T_CHECK(fixture_close(&f->writer) == 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) < IO_BUFSIZE);
	f->reader = deflate_variants[variant].reader(err_memreader(
		EIO, VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
	T_CHECK(f->reader != NULL);

	size_t total = 0;
	int err = 0;
	while (total < N && err == 0) {
		const void *buf = NULL;
		size_t n = chunk;
		err = io_stream_direct_read(f->reader, &buf, &n);
		if (n == 0 || n > N - total) {
			break;
		}
		memcpy(f->output + total, buf, n);
		total += n;
	}
	const bool matched = memcmp(f->output, zeros, N) == 0;
	const void *buf = NULL;
	size_t n = chunk;
	const int next_err = io_stream_direct_read(f->reader, &buf, &n);
	const int close_err = fixture_close(&f->reader);
	VBUF_FREE(f->compressed);
	free(f->output);
	f->output = NULL;

	T_EXPECT_EQ(total, (size_t)N);
	T_EXPECT(matched);
	T_EXPECT_EQ(err, EIO);
	T_EXPECT_EQ(next_err, EIO);
	T_EXPECT_EQ(n, (size_t)0);
	T_EXPECT_EQ(close_err, 0);
}

T_DECLARE_CASE(codec_inflate_drains_output_before_base_error)
{
	const size_t chunks[] = { 32785, 1000 };
	for (size_t variant = 0; variant < ARRAY_SIZE(deflate_variants);
	     variant++) {
		for (size_t k = 0; k < ARRAY_SIZE(chunks); k++) {
			T_CALL_SUBCASE(
				expect_inflate_drains_before_base_error,
				variant, chunks[k]);
		}
	}
}

/* The gzip body decoder drains pending output the same way: with the trailer
 * cut off, every body byte is delivered before the short trailer fails. */
T_DECLARE_CASE(codec_gzip_drains_output_before_short_trailer)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 32785 };
	static const uint_least8_t zeros[N] = { 0 };
	/* one spare byte so a read of everything also hits the error */
	f->output = malloc(N + 1);
	T_CHECK(f->output != NULL);

	f->compressed = VBUF_NEW(64);
	T_CHECK(f->compressed != NULL);
	f->writer = codec_gzip_writer(io_heapwriter(&f->compressed));
	T_CHECK(f->writer != NULL);
	T_EXPECT(stream_write_all(f->writer, zeros, N));
	T_EXPECT_EQ(fixture_close(&f->writer), 0);
	T_CHECK(f->compressed != NULL && VBUF_LEN(f->compressed) > 8);

	/* drop the 8-byte CRC-32/ISIZE trailer */
	f->reader = codec_gzip_reader(io_memreader(
		VBUF_DATA(f->compressed), VBUF_LEN(f->compressed) - 8));
	T_CHECK(f->reader != NULL);
	memset(f->output, 0xff, N + 1);
	size_t n = N + 1;
	T_EXPECT(io_stream_read(f->reader, f->output, &n) != 0);
	T_EXPECT_EQ(n, (size_t)N);
	T_EXPECT_MEMEQ(f->output, zeros, N);
	(void)fixture_close(&f->reader);
	VBUF_FREE(f->compressed);
	free(f->output);
	f->output = NULL;
}

/* The zlib/raw-deflate writers must resume after a base short-write: write,
 * full flush and finish each return -1 while output is staged, and the retried
 * call carries on from where the base stopped, so the stream still decodes
 * whole. Input large enough to cross a block boundary exercises the drain of a
 * block held inside the compressor across the -1 returns as well. */
T_DECLARE_CASE(codec_deflate_writer_resumes_after_short_write)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 40000, CHUNK = 97 };
	f->src = malloc(N);
	f->output = malloc(N);
	T_CHECK(f->src != NULL);
	T_CHECK(f->output != NULL);
	fill_random(f->src, N);

	for (size_t v = 0; v < ARRAY_SIZE(deflate_variants); ++v) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);
		struct io_stream *base =
			choke_memwriter(&f->compressed, 0, CHUNK);
		T_CHECK(base != NULL);
		f->writer = deflate_variants[v].writer(base);
		T_CHECK(f->writer != NULL);

		size_t total = 0;
		size_t shorts = 0;
		int guard = 0;
		while (total < N && guard++ < 1000000) {
			size_t n = N - total;
			const int err =
				io_stream_write(f->writer, f->src + total, &n);
			total += n;
			T_CHECK(err == 0 || err == -1);
			shorts += (err == -1);
		}
		T_EXPECT_EQ(total, (size_t)N);
		T_EXPECT(shorts > 0);

		int ret;
		shorts = 0;
		guard = 0;
		do {
			ret = io_stream_flush(f->writer);
			T_CHECK(ret == 0 || ret == -1);
			shorts += (ret == -1);
		} while (ret == -1 && guard++ < 1000000);
		T_EXPECT_EQ(ret, 0);
		T_EXPECT(shorts > 0);
		T_CHECK(f->compressed != NULL);
		{
			f->reader = deflate_variants[v].reader(io_memreader(
				VBUF_DATA(f->compressed),
				VBUF_LEN(f->compressed)));
			T_CHECK(f->reader != NULL);
			memset(f->output, 0, N);
			T_EXPECT(stream_read_exact(f->reader, f->output, N));
			T_EXPECT_MEMEQ(f->output, f->src, N);
			(void)fixture_close(&f->reader);
		}

		/* close cannot be retried: let the finish through whole */
		((struct choke_memwriter *)base)->chunk = SIZE_MAX;
		T_EXPECT_EQ(fixture_close(&f->writer), 0);

		f->reader = deflate_variants[v].reader(io_memreader(
			VBUF_DATA(f->compressed), VBUF_LEN(f->compressed)));
		T_CHECK(f->reader != NULL);
		memset(f->output, 0, N);
		T_EXPECT(stream_read_exact(f->reader, f->output, N));
		T_EXPECT(stream_at_eof(f->reader));
		T_EXPECT_EQ(fixture_close(&f->reader), 0);
		T_EXPECT_MEMEQ(f->output, f->src, N);
		VBUF_FREE(f->compressed);
	}
	free(f->src);
	f->src = NULL;
	free(f->output);
	f->output = NULL;
}

/* A base write error surfaces unchanged from the zlib/raw-deflate writers'
 * write, flush and close. */
T_DECLARE_CASE(codec_deflate_writer_surfaces_base_error)
{
	struct codec_fixture *f = codec_fixture_new();
	T_CLEANUP(codec_fixture_cleanup, f);

	enum { N = 40000, SENTINEL = -7 };
	f->src = malloc(N);
	T_CHECK(f->src != NULL);
	fill_random(f->src, N);

	for (size_t v = 0; v < ARRAY_SIZE(deflate_variants); ++v) {
		f->compressed = VBUF_NEW(64);
		T_CHECK(f->compressed != NULL);
		struct io_stream *base = choke_memwriter(&f->compressed, 0, 0);
		T_CHECK(base != NULL);
		((struct choke_memwriter *)base)->err = SENTINEL;

		/* write: a full block is emitted mid-write */
		f->writer = deflate_variants[v].writer(base);
		T_CHECK(f->writer != NULL);
		size_t n = N;
		T_EXPECT_EQ(
			io_stream_write(f->writer, f->src, &n), (int)SENTINEL);
		T_EXPECT(n < (size_t)N);
		T_EXPECT_EQ(fixture_close(&f->writer), (int)SENTINEL);

		/* flush, then close, of a small buffered payload */
		base = choke_memwriter(&f->compressed, 0, 0);
		T_CHECK(base != NULL);
		((struct choke_memwriter *)base)->err = SENTINEL;
		f->writer = deflate_variants[v].writer(base);
		T_CHECK(f->writer != NULL);
		T_EXPECT(stream_write_all(f->writer, f->src, 100));
		T_EXPECT_EQ(io_stream_flush(f->writer), (int)SENTINEL);
		T_EXPECT_EQ(fixture_close(&f->writer), (int)SENTINEL);
		VBUF_FREE(f->compressed);
	}
	free(f->src);
	f->src = NULL;
}

T_DECLARE_CASE(codec_failed_expectation_cleans_fixture)
{
	static const struct {
		const char *name;
		void (*test)(struct testing_ctx *);
		enum fixture_failure failure;
	} cases[] = {
		{ "writer", testcase_codec_zlib_roundtrip_,
		  FIXTURE_FAIL_WRITE },
		{ "reader", testcase_codec_deflate_roundtrip_,
		  FIXTURE_FAIL_READ },
		{ "close", testcase_codec_gzip_roundtrip_, FIXTURE_FAIL_CLOSE },
		{ "heap_buffers", testcase_codec_decompress_ring_wraparound_,
		  FIXTURE_FAIL_WRITE },
		{ "short_write",
		  testcase_codec_deflate_writer_resumes_after_short_write_,
		  FIXTURE_FAIL_READ },
		{ "lua_file", testcase_codec_lua_reader_passthrough_plain_file_,
		  FIXTURE_FAIL_LUA_SOURCE },
	};
	T_DECLARE_CTX(nested);
	for (size_t i = 0; i < ARRAY_SIZE(cases); ++i) {
		const size_t live = fixture_live;
		fixture_failed_path[0] = '\0';
		fixture_failure = cases[i].failure;
		testing_run_case_(&nested, cases[i].name, cases[i].test);
		T_EXPECT_EQ(nested.failed, i + 1);
		T_EXPECT_EQ(fixture_live, live);
		T_EXPECT_EQ(fixture_failure, FIXTURE_FAIL_NONE);
		if (cases[i].failure == FIXTURE_FAIL_LUA_SOURCE) {
			T_EXPECT(fixture_failed_path[0] != '\0');
			T_EXPECT_EQ(access(fixture_failed_path, F_OK), -1);
			T_EXPECT_EQ(errno, ENOENT);
		}
		testing_run_case_(&nested, cases[i].name, cases[i].test);
		T_EXPECT_EQ(nested.passed, i + 1);
		T_EXPECT_EQ(fixture_live, live);
	}
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(codec_failed_expectation_cleans_fixture),
	T_CASE(codec_writer_constructor_allocation_failure_closes_base),
	T_CASE(codec_reader_constructor_allocation_failure_closes_base),
	T_CASE(codec_gzip_constructor_header_failure_closes_base),
	T_CASE(codec_lua_reader_rejects_unsupported_boms),
	T_CASE(codec_gzip_optional_headers_across_refills),
	T_CASE(codec_inflate_corrupt_and_truncated_fails),
	T_CASE(codec_gzip_finish_resumes_after_short_write),
	T_CASE(codec_inflate_surfaces_base_error),
	T_CASE(codec_deflate_writer_emits_final_block),
	T_CASE(codec_deflate_writer_close_emits_final_block),
	T_CASE(codec_inflate_drains_output_after_input_ends),
	T_CASE(codec_inflate_drains_output_before_base_error),
	T_CASE(codec_gzip_drains_output_before_short_trailer),
	T_CASE(codec_deflate_writer_resumes_after_short_write),
	T_CASE(codec_deflate_writer_surfaces_base_error),
	T_CASE(codec_lua_reader_strips_shebang),
	T_CASE(codec_lua_reader_strips_bom_and_shebang),
	T_CASE(codec_lua_reader_strips_bom_only),
	T_CASE(codec_lua_reader_small_first_read),
	T_CASE(codec_lua_reader_gunzips_source),
	T_CASE(codec_lua_reader_passthrough_plain_file),
	T_CASE(codec_lua_reader_bom_only_no_content),
	T_CASE(codec_lua_reader_empty_stream),
	T_CASE(codec_lua_reader_shebang_newline_on_chunk_boundary),
	T_CASE(codec_null_base),
	T_CASE(codec_zlib_roundtrip),
	T_CASE(codec_reader_aborts_decompression_bomb),
	T_CASE(codec_gzip_accepts_cumulative_limit),
	T_CASE(codec_gzip_rejects_cumulative_limit_plus_one),
	T_CASE(codec_reader_wraps_base_without_direct_read),
	T_CASE(codec_reader_short_direct_read_is_not_eof),
	T_CASE(codec_gzip_truncated_header_via_short_reads_fails),
	T_CASE(codec_deflate_roundtrip),
	T_CASE(codec_gzip_roundtrip),
	T_CASE(codec_decompress_ring_wraparound),
	T_CASE(codec_gzip_multiframe),
	T_CASE(codec_gzip_crc_error),
	T_CASE(codec_gzip_isize_error),
	T_CASE(codec_gzip_flush_multiframe),
	T_CASE(codec_gzip_flush_empty),
	T_CASE(codec_gzip_optional_headers),
	T_CASE(codec_gzip_text_headers_use_buffered_spans),
	T_CASE(codec_gzip_empty_fname_after_fextra),
	T_CASE(codec_zlib_flush_then_continue),
	T_CASE(codec_zlib_corrupt_input_fails),
	T_CASE(codec_zlib_adler32_mismatch),
	T_CASE(codec_zlib_adler32_mismatch_surfaced_at_close),
	T_CASE(codec_gzip_hcrc_mismatch),
	T_CASE(codec_gzip_read_errors_are_terminal),
	T_CASE(codec_gzip_bad_magic),
	T_CASE(codec_gzip_rejects_reserved_flag_bits),
	T_CASE(codec_gzip_truncated_after_fextra),
	T_CASE(codec_gzip_truncated_body_fails),
	T_CASE(codec_gzip_short_trailer_fails),
	T_BENCH(bench_zlib_roundtrip),
	T_BENCH(bench_gzip_roundtrip),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
