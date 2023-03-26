/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef FORMATS_H
#define FORMATS_H

#include "stddef.h"
#include "stdint.h"

size_t format_iec(char *buf, size_t bufsize, size_t value);

struct duration {
	signed int sign;
	unsigned int days;
	unsigned int hours;
	unsigned int minutes;
	unsigned int seconds;
	unsigned int millis;
	unsigned int micros;
	unsigned int nanos;
};

struct duration make_duration(double seconds);
struct duration make_duration_nanos(int64_t nanos);

int format_duration_seconds(char *b, size_t size, struct duration d);

#endif /* FORMATS_H */
