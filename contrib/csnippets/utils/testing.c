/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "testing.h"

#include "formats.h"

#ifdef _WIN32
#include "wintime.h"
#else
#include "os/clock.h"
#endif

#include <regex.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Return whether `name` is selected: an absent filter selects everything. */
static bool name_matches(const regex_t *re, const char *name)
{
	return re == NULL || regexec(re, name, 0, NULL, 0) == 0;
}

/* Run a single case, mirroring the T_RUN_CASE macro. */
static void run_case(struct testing_ctx *t, const struct testing_suite *e)
{
	t->current = e->name;
	t->case_failed = false;
	t->case_skipped = false;
	(void)fprintf(t->out, "=== RUN   %s\n", e->name);
	(void)fflush(t->out);
	if (setjmp(t->case_jmp) == 0) {
		e->fn.test(t);
	}
	if (t->case_failed) {
		t->failed++;
		(void)fprintf(t->out, "--- FAIL  %s\n", e->name);
	} else if (t->case_skipped) {
		t->skipped++;
		(void)fprintf(t->out, "--- SKIP  %s\n", e->name);
	} else {
		t->passed++;
		(void)fprintf(t->out, "--- PASS  %s\n", e->name);
	}
	(void)fflush(t->out);
}

/* Run a single benchmark: double N until at least one second of wall time has
 * elapsed, then report ns/op alongside B/op and allocs/op.  This backs the
 * T_RUN_BENCH macro, so the monotonic clock stays here and test files need not
 * include measure.h. */
void testing_bench_run(
	struct testing_ctx *t, const char *name,
	void (*bench)(struct testing_bench *))
{
	(void)fprintf(t->out, "=== RUN   %s\n", name);
	(void)fflush(t->out);
	struct testing_bench b = { 0 };
	const int_fast64_t start = clock_monotonic_ns();
	int_fast64_t elapsed;
	uint_fast64_t n = 1;
	do {
		b.N = n;
		bench(&b);
		n <<= 1u;
		elapsed = clock_monotonic_ns() - start;
	} while (n != 0 && elapsed < 1000000000 /* 1s */);
	const uint_fast64_t iters = n - 1;

	/* per-op wall time, rendered as an SI-prefixed duration (e.g. 28.1µs/op) */
	char timebuf[32];
	(void)format_si_prefix(
		timebuf, sizeof(timebuf),
		(double)elapsed / (double)iters * 1e-9);
	/* per-op heap footprint, rendered with IEC units (e.g. 1.50KiB/op) */
	char membuf[32];
	(void)format_iec_bytes(
		membuf, sizeof(membuf), (double)b.bytes / (double)iters);

	(void)fprintf(
		t->out, "--- BENCH %s\t%ju\t%ss/op", name, (uintmax_t)iters,
		timebuf);
	if (b.set_bytes != 0) {
		/* throughput in bytes per second, SI-prefixed (e.g. 2.33GB/s) */
		char tputbuf[32];
		(void)format_si_prefix(
			tputbuf, sizeof(tputbuf),
			(double)b.set_bytes * (double)iters / (double)elapsed *
				1e9);
		(void)fprintf(t->out, "\t%sB/s", tputbuf);
	}
	(void)fprintf(
		t->out, "\t%s/op\t%ju allocs/op\n", membuf,
		(uintmax_t)(b.allocs / iters));
	(void)fflush(t->out);
	t->benched++;
}

/* Run a benchmark suite entry through testing_bench_run. */
static void run_bench(struct testing_ctx *t, const struct testing_suite *e)
{
	testing_bench_run(t, e->name, e->fn.bench);
}

int testing_main(int argc, char *const *argv, const struct testing_suite *suite)
{
	/* The --run option overrides the TESTING_FILTER environment variable. */
	const char *filter = NULL;
	bool have_run = false;
	for (int i = 1; i < argc; i++) {
		const char *const arg = argv[i];
		if (strncmp(arg, "--run=", sizeof("--run=") - 1) == 0) {
			filter = arg + (sizeof("--run=") - 1);
			have_run = true;
		} else if (strcmp(arg, "--run") == 0) {
			if (++i >= argc) {
				(void)fprintf(
					stderr,
					"testing: option '--run' requires a regex argument\n");
				return EXIT_FAILURE;
			}
			filter = argv[i];
			have_run = true;
		} else {
			(void)fprintf(
				stderr,
				"testing: unrecognized argument '%s'\n"
				"usage: [--run <posix-ere>] (or set TESTING_FILTER)\n",
				arg);
			return EXIT_FAILURE;
		}
	}
	if (!have_run) {
		filter = getenv("TESTING_FILTER");
	}
	if (filter != NULL && filter[0] == '\0') {
		/* an empty filter is treated as no filter at all */
		filter = NULL;
	}

	regex_t re;
	const regex_t *rep = NULL;
	if (filter != NULL) {
		const int err = regcomp(&re, filter, REG_EXTENDED | REG_NOSUB);
		if (err != 0) {
			char errbuf[128];
			(void)regerror(err, &re, errbuf, sizeof(errbuf));
			(void)fprintf(
				stderr, "testing: invalid regex \"%s\": %s\n",
				filter, errbuf);
			return EXIT_FAILURE;
		}
		rep = &re;
	}

	struct testing_ctx ctx = { .out = stderr };
	/* Cases first, in suite order. */
	for (const struct testing_suite *e = suite; e->name != NULL; e++) {
		if (e->kind == TESTING_CASE && name_matches(rep, e->name)) {
			run_case(&ctx, e);
		}
	}
	/* Benches last, and only when a filter is active. */
	if (rep != NULL) {
		for (const struct testing_suite *e = suite; e->name != NULL;
		     e++) {
			if (e->kind == TESTING_BENCH &&
			    name_matches(rep, e->name)) {
				run_bench(&ctx, e);
			}
		}
		regfree(&re);
	}

	if (filter != NULL &&
	    ctx.passed + ctx.failed + ctx.skipped + ctx.benched == 0) {
		(void)fprintf(
			stderr, "testing: no entries matched \"%s\"\n", filter);
	}
	(void)fprintf(
		ctx.out,
		"=== DONE  %d passed, %d failed, %d skipped, %d benched\n",
		ctx.passed, ctx.failed, ctx.skipped, ctx.benched);
	(void)fflush(ctx.out);
	return T_RESULT(ctx) ? EXIT_SUCCESS : EXIT_FAILURE;
}
