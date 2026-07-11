/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "file.h"

#include "stream.h"
#include "utils/slog.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int file_read(void *p, void *buf, size_t *restrict len)
{
	struct stream *restrict s = p;
	FILE *f = s->data;
	*len = fread(buf, sizeof(unsigned char), *len, f);
	return ferror(f);
}

static int file_write(void *p, const void *buf, size_t *restrict len)
{
	struct stream *restrict s = p;
	FILE *f = s->data;
	*len = fwrite(buf, sizeof(unsigned char), *len, f);
	return ferror(f);
}

static int file_flush(void *p)
{
	struct stream *restrict s = p;
	FILE *f = s->data;
	return fflush(f);
}

static int file_close(void *p)
{
	struct stream *restrict s = p;
	int ret = 0;
	FILE *f = s->data;
	/* ISO C does not forbid calling fclose on stdin, stdout or stderr,
	 * but using the streams afterward causes undefined behavior. */
	if (f != stdin && f != stdout && f != stderr) {
		ret = fclose(f);
	}
	free(s);
	return ret;
}

struct stream *io_filereader(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		const int err = errno;
		LOGE_F("setvbuf: (%d) %s", err, strerror(err));
	}
	struct stream *restrict s = malloc(sizeof(struct stream));
	if (s == NULL) {
		if (fclose(f) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
		}
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.read = file_read,
		.close = file_close,
	};
	*s = (struct stream){ &vftable, f };
	return s;
}

struct stream *io_filewriter(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		const int err = errno;
		LOGE_F("setvbuf: (%d) %s", err, strerror(err));
	}
	struct stream *restrict s = malloc(sizeof(struct stream));
	if (s == NULL) {
		if (fclose(f) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
		}
		return NULL;
	}
	static const struct stream_vftable vftable = {
		.write = file_write,
		.flush = file_flush,
		.close = file_close,
	};
	*s = (struct stream){ &vftable, f };
	return s;
}

unsigned char *io_readfile(const char *path, size_t *len)
{
	if (!path || !len) {
		return NULL;
	}
	FILE *fp = fopen(path, "r");
	if (!fp) {
		return NULL;
	}
	void *buf = malloc(*len);
	if (!buf) {
		if (fclose(fp) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
		}
		return NULL;
	}
	const size_t nread = fread(buf, 1, *len, fp);
	/* fread returns a short count for both clean EOF and a genuine read
	 * error; ferror() must be checked before fclose() invalidates fp */
	const bool read_error = ferror(fp) != 0;
	if (fclose(fp) != 0) {
		const int err = errno;
		LOGE_F("fclose: (%d) %s", err, strerror(err));
	}
	if (read_error) {
		LOGE("io_readfile: read error");
		free(buf);
		return NULL;
	}
	if (nread >= *len) {
		free(buf);
		return NULL;
	}
	unsigned char *out = realloc(buf, nread + 1);
	if (!out) {
		out = buf;
	}
	*len = nread;
	out[nread] = '\0';
	return out;
}

bool io_writefile(
	const char *restrict path, const unsigned char *restrict data,
	size_t *restrict len)
{
	if (!path || !data || !len) {
		return false;
	}
	FILE *fp = fopen(path, "w");
	if (!fp) {
		return false;
	}
	const size_t nwrite = fwrite(data, 1, *len, fp);
	const bool short_write = nwrite != *len;
	const bool close_failed = fclose(fp) != 0;
	if (close_failed) {
		const int err = errno;
		LOGE_F("fclose: (%d) %s", err, strerror(err));
	}
	*len = nwrite;
	return !short_write && !close_failed;
}

const char *io_readutf8(const unsigned char *data, size_t *len)
{
	if (!data || !len) {
		return NULL;
	}
	if (*len >= 3 && data[0] == 0xEF && data[1] == 0xBB &&
	    data[2] == 0xBF) {
		*len -= 3;
		return (const char *)(data + 3);
	}
	if (*len >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) ||
			  (data[0] == 0xFE && data[1] == 0xFF))) {
		return NULL;
	}
	/* UTF-32BE BOM. The UTF-32LE BOM (FF FE 00 00) is already rejected by
	 * the UTF-16LE check above (its FF FE prefix), so only the BE form
	 * needs a dedicated test here. */
	if (*len >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
	    data[2] == 0xFE && data[3] == 0xFF) {
		return NULL;
	}
	return (const char *)data;
}
