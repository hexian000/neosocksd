#include "file.h"

#include <stdio.h>
#include <stdlib.h>

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
	FILE *f = s->data;
	const int ret = fclose(f);
	free(s);
	return ret;
}

struct stream *io_filereader(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	(void)setvbuf(f, NULL, _IONBF, 0);
	struct stream *restrict s = malloc(sizeof(struct stream));
	if (s == NULL) {
		fclose(f);
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
	(void)setvbuf(f, NULL, _IONBF, 0);
	struct stream *restrict s = malloc(sizeof(struct stream));
	if (s == NULL) {
		fclose(f);
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
