/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "testing.h"

#include "formats.h"
#ifdef _WIN32
#include "wintime.h"
#else
#include "os/clock.h"
#endif

#include <errno.h>
#include <limits.h>
#if HAVE_REGEX_H
#include <regex.h>
#endif
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* volatile sinks backing T_KEEP (see the dead-code-elimination notes in
 * testing.h).  Defined once here so every test binary shares one set. */
volatile unsigned long long testing_keep_uint_;
volatile long double testing_keep_flt_;
const void *volatile testing_keep_ptr_;

/*
 * A compiled name filter.  With POSIX regex available it is an extended regular
 * expression; without it (pure ISO C11) it degrades to a literal unanchored
 * substring match, which coincides for plain names without metacharacters.
 */
struct filter {
	bool active;
#if HAVE_REGEX_H
	regex_t re;
#else
	const char *pat;
#endif
};

/* Compile `pattern` into `*f`; on error print a message naming `opt`. */
static bool
filter_compile(struct filter *f, const char *pattern, const char *opt)
{
	f->active = false;
#if HAVE_REGEX_H
	const int err = regcomp(&f->re, pattern, REG_EXTENDED | REG_NOSUB);
	if (err != 0) {
		char errbuf[128];
		(void)regerror(err, &f->re, errbuf, sizeof(errbuf));
		(void)fprintf(
			stderr, "testing: invalid %s regex \"%s\": %s\n", opt,
			pattern, errbuf);
		return false;
	}
#else /* HAVE_REGEX_H */
	(void)opt;
	f->pat = pattern;
#endif /* HAVE_REGEX_H */
	f->active = true;
	return true;
}

/* Whether `name` is selected; an inactive filter selects everything. */
static bool filter_match(const struct filter *f, const char *name)
{
	if (!f->active) {
		return true;
	}
#if HAVE_REGEX_H
	return regexec(&f->re, name, 0, NULL, 0) == 0;
#else
	return strstr(name, f->pat) != NULL;
#endif
}

static void filter_free(struct filter *f)
{
#if HAVE_REGEX_H
	if (f->active) {
		regfree(&f->re);
	}
#else
	(void)f;
#endif
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

/* -------------------------------------------------------------------------
 * Benchmark timer control (T_BENCH_RESET_TIMER / STOP / START).  The monotonic
 * clock lives here so benchmark files need not include it.
 * ---------------------------------------------------------------------- */

void testing_bench_stop_timer(struct testing_bench *b)
{
	if (b->pause_at < 0) { /* currently running */
		b->pause_at = clock_monotonic_ns();
	}
}

void testing_bench_start_timer(struct testing_bench *b)
{
	if (b->pause_at >= 0) { /* currently stopped */
		b->paused_ns += clock_monotonic_ns() - b->pause_at;
		b->pause_at = -1;
	}
}

void testing_bench_reset_timer(struct testing_bench *b)
{
	const int_fast64_t now = clock_monotonic_ns();
	b->round_start = now;
	b->paused_ns = 0;
	if (b->pause_at >= 0) { /* keep a stopped timer stopped, from now */
		b->pause_at = now;
	}
}

/* Run the benchmark body once at the current b->N and return the active
 * (timer-on) time in nanoseconds, honoring any STOP/START/RESET calls. */
static int_fast64_t
bench_once(void (*bench)(struct testing_bench *), struct testing_bench *b)
{
	b->round_start = clock_monotonic_ns();
	b->paused_ns = 0;
	b->pause_at = -1; /* running */
	bench(b);
	const int_fast64_t end = clock_monotonic_ns();
	if (b->pause_at >= 0) { /* ended while stopped */
		b->paused_ns += end - b->pause_at;
		b->pause_at = -1;
	}
	const int_fast64_t active = (end - b->round_start) - b->paused_ns;
	return active > 0 ? active : 0;
}

/* Run a single benchmark and report ns/op with B/op, allocs/op and optional
 * throughput.  Calibration doubles N until at least `bench_time_ns` of active
 * time has elapsed (default 1s); a fixed count (--benchtime Nx) instead runs
 * once, and --count repeats the whole measurement and reports the minimum ns/op
 * (min of N).  This backs the T_RUN_BENCH macro, so the monotonic clock stays
 * here and test files need not include measure.h. */
void testing_bench_run(
	struct testing_ctx *t, const char *name,
	void (*bench)(struct testing_bench *))
{
	(void)fprintf(t->out, "=== RUN   %s\n", name);
	(void)fflush(t->out);

	const int_fast64_t time_ns =
		t->bench_time_ns > 0 ? t->bench_time_ns : 1000000000 /* 1s */;
	const uint_fast64_t fixed_n = t->bench_fixed_n;
	const int reps = t->bench_count > 0 ? t->bench_count : 1;

	/* Best (minimum ns/op) measurement across the repeats. */
	double best_ns_per_op = 0.0;
	int_fast64_t best_elapsed = 0;
	uint_fast64_t best_iters = 0, best_bytes = 0, best_allocs = 0;
	uint_fast64_t set_bytes = 0;

	for (int rep = 0; rep < reps; rep++) {
		struct testing_bench b = { 0 };
		int_fast64_t elapsed;
		uint_fast64_t iters;
		if (fixed_n != 0) {
			/* Fixed iteration count: one run, no time-based scaling. */
			b.N = fixed_n;
			elapsed = bench_once(bench, &b);
			iters = fixed_n;
		} else {
			/* Geometric calibration.  Each round runs as many iterations
			 * as all previous rounds combined plus one, so the running
			 * total covers every iteration and the accumulated active time
			 * matches them - no work is wasted. */
			int_fast64_t active = 0;
			uint_fast64_t total = 0;
			uint_fast64_t n = 1;
			for (;;) {
				b.N = n;
				active += bench_once(bench, &b);
				total += n;
				if (active >= time_ns) {
					break;
				}
				if (n > (UINT64_MAX >> 1)) {
					/* Doubling would overflow before reaching the
					 * time target.  Completing 2^63 iterations in
					 * under `time_ns` is physically impossible, so the
					 * benchmarked work was almost certainly optimized
					 * away.  Report a hard failure rather than a
					 * meaningless ~0 ns/op number. */
					(void)fprintf(
						t->out,
						"--- FAIL  %s\tno measurable work; the benchmarked "
						"operation was likely optimized away (use T_KEEP on its result)\n",
						name);
					(void)fflush(t->out);
					t->failed++;
					return;
				}
				n <<= 1u;
			}
			elapsed = active;
			iters = total;
		}
		const double ns_per_op = (double)elapsed / (double)iters;
		if (rep == 0 || ns_per_op < best_ns_per_op) {
			best_ns_per_op = ns_per_op;
			best_elapsed = elapsed;
			best_iters = iters;
			best_bytes = b.bytes;
			best_allocs = b.allocs;
			set_bytes = b.set_bytes;
		}
	}

	/* per-op wall time, rendered as an SI-prefixed duration (e.g. 28.1µs/op) */
	char timebuf[32];
	(void)format_si_prefix(timebuf, sizeof(timebuf), best_ns_per_op * 1e-9);
	/* per-op heap footprint, rendered with IEC units (e.g. 1.50KiB/op) */
	char membuf[32];
	(void)format_iec_bytes(
		membuf, sizeof(membuf),
		(double)best_bytes / (double)best_iters);

	/* Fixed-width columns so successive benchmarks line up when read together.
	 * The optional throughput and "min of N" notes trail the fixed columns. */
	char timecol[48], memcol[48], alloccol[48];
	(void)snprintf(timecol, sizeof(timecol), "%ss/op", timebuf);
	(void)snprintf(memcol, sizeof(memcol), "%s/op", membuf);
	(void)snprintf(
		alloccol, sizeof(alloccol), "%ju allocs/op",
		(uintmax_t)(best_allocs / best_iters));
	(void)fprintf(
		t->out, "--- BENCH %-28s %14ju %13s %13s %16s", name,
		(uintmax_t)best_iters, timecol, memcol, alloccol);
	if (set_bytes != 0 && best_elapsed > 0) {
		/* throughput in bytes per second, SI-prefixed (e.g. 2.33GB/s);
		 * skipped when the elapsed time rounds to zero (e.g. a single
		 * fast op under --benchtime 1x) to avoid dividing by zero */
		char tputbuf[32];
		(void)format_si_prefix(
			tputbuf, sizeof(tputbuf),
			(double)set_bytes * (double)best_iters /
				(double)best_elapsed * 1e9);
		(void)fprintf(t->out, " %12sB/s", tputbuf);
	}
	if (reps > 1) {
		(void)fprintf(t->out, " (min of %d)", reps);
	}
	(void)fprintf(t->out, "\n");
	(void)fflush(t->out);
	t->benched++;
}

/* Run a benchmark suite entry through testing_bench_run. */
static void run_bench(struct testing_ctx *t, const struct testing_suite *e)
{
	testing_bench_run(t, e->name, e->fn.bench);
}

/*
 * Match argv[*i] against option `flag`.  Returns 1 and sets *value on a match
 * ("--flag=value" in place, or "--flag value" consuming the next argument), 0
 * when `flag` is absent, or -1 when it matches but its value is missing.
 */
static int opt_value(
	const char *flag, int argc, char *const *argv, int *i,
	const char **value)
{
	const char *const arg = argv[*i];
	const size_t len = strlen(flag);
	if (strncmp(arg, flag, len) != 0) {
		return 0;
	}
	if (arg[len] == '=') {
		*value = arg + len + 1;
		return 1;
	}
	if (arg[len] == '\0') {
		if (*i + 1 >= argc) {
			return -1;
		}
		*value = argv[++(*i)];
		return 1;
	}
	return 0; /* a longer option that merely shares this prefix */
}

/*
 * Parse a --benchtime value.  "<count>x" selects a fixed iteration count (into
 * *fixed_n); otherwise a duration "<number>[ns|us|ms|s|m]" (bare number means
 * seconds) goes into *time_ns.  Returns false on a malformed, non-positive, or
 * out-of-range value (a fixed count must be a whole number >= 1).  Exactly one
 * of the two outputs is left non-zero on success.
 */
static bool
parse_benchtime(const char *s, int_fast64_t *time_ns, uint_fast64_t *fixed_n)
{
	char *end;
	const double v = strtod(s, &end);
	if (end == s || !(v > 0.0)) {
		return false;
	}
	if (strcmp(end, "x") == 0) {
		/* A fixed count must be a whole number >= 1 and representable;
		 * reject a fractional (<1) or out-of-range value instead of
		 * silently truncating it to 0 (which falls back to timed mode).
		 * The upper bound keeps the cast within uint_fast64_t. */
		if (!(v >= 1.0 && v < 0x1p64)) {
			return false;
		}
		*fixed_n = (uint_fast64_t)v;
		*time_ns = 0;
		return true;
	}
	double scale; /* to seconds */
	if (*end == '\0' || strcmp(end, "s") == 0) {
		scale = 1.0;
	} else if (strcmp(end, "ms") == 0) {
		scale = 1e-3;
	} else if (strcmp(end, "us") == 0) {
		scale = 1e-6;
	} else if (strcmp(end, "ns") == 0) {
		scale = 1e-9;
	} else if (strcmp(end, "m") == 0) {
		scale = 60.0;
	} else {
		return false;
	}
	const double ns = v * scale * 1e9;
	/* Reject sub-nanosecond and out-of-range durations; the upper bound keeps
	 * the value representable as int_fast64_t (>=2^63 would overflow the
	 * cast, which is undefined behavior). */
	if (!(ns >= 1.0 && ns < 0x1p63)) {
		return false;
	}
	*time_ns = (int_fast64_t)ns;
	*fixed_n = 0;
	return true;
}

/* Wraps opt_value so callers test a plain bool instead of assigning *r
 * inside the condition itself. */
static bool match_opt(
	const char *flag, int argc, char *const *argv, int *i,
	const char **value, int *r)
{
	*r = opt_value(flag, argc, argv, i, value);
	return *r != 0;
}

int testing_main(int argc, char *const *argv, const struct testing_suite *suite)
{
	/*
	 * --run <ere>   select test cases (absent: all cases run)
	 * --bench <ere> select benchmarks (absent: no benchmark runs)
	 * --benchtime <dur>|<n>x   per-bench wall time, or a fixed count
	 * --count <n>   repeat each benchmark, reporting the minimum ns/op
	 * A flag overrides its environment fallback (TESTING_FILTER / TESTING_BENCH).
	 */
	const char *run = NULL, *bench = NULL;
	bool have_run = false, have_bench = false;
	int_fast64_t bench_time_ns = 0;
	uint_fast64_t bench_fixed_n = 0;
	int bench_count = 1;
	static const char usage[] = "usage: [--run <ere>] [--bench <ere>] "
				    "[--benchtime <dur>|<n>x] [--count <n>]\n";
	for (int i = 1; i < argc; i++) {
		const char *value = NULL;
		int r;
		if (match_opt("--run", argc, argv, &i, &value, &r)) {
			run = value;
			have_run = true;
		} else if (match_opt("--bench", argc, argv, &i, &value, &r)) {
			bench = value;
			have_bench = true;
		} else if (match_opt("--benchtime", argc, argv, &i, &value, &r)) {
			if (r > 0 &&
			    !parse_benchtime(
				    value, &bench_time_ns, &bench_fixed_n)) {
				(void)fprintf(
					stderr,
					"testing: invalid --benchtime value '%s'\n",
					value);
				return EXIT_FAILURE;
			}
		} else if (match_opt("--count", argc, argv, &i, &value, &r)) {
			char *end = NULL;
			errno = 0;
			const long c = (r > 0) ? strtol(value, &end, 10) : 0;
			if (r > 0 && (end == value || *end != '\0' ||
				      errno != 0 || c < 1 || c > INT_MAX)) {
				(void)fprintf(
					stderr,
					"testing: invalid --count value '%s'\n",
					value);
				return EXIT_FAILURE;
			}
			bench_count = (int)c;
		} else {
			(void)fprintf(
				stderr,
				"testing: unrecognized argument '%s'\n%s",
				argv[i], usage);
			return EXIT_FAILURE;
		}
		if (r < 0) {
			(void)fprintf(
				stderr,
				"testing: option '%s' requires a value\n%s",
				argv[i], usage);
			return EXIT_FAILURE;
		}
	}

	/* Environment fallbacks apply only when the matching flag is absent. */
	if (!have_run) {
		run = getenv("TESTING_FILTER");
	}
	if (!have_bench) {
		bench = getenv("TESTING_BENCH");
	}
	/* An empty pattern is treated as absent. */
	if (run != NULL && run[0] == '\0') {
		run = NULL;
	}
	if (bench != NULL && bench[0] == '\0') {
		bench = NULL;
	}

	struct filter run_f = { 0 }, bench_f = { 0 };
	if (run != NULL && !filter_compile(&run_f, run, "--run")) {
		return EXIT_FAILURE;
	}
	if (bench != NULL && !filter_compile(&bench_f, bench, "--bench")) {
		filter_free(&run_f);
		return EXIT_FAILURE;
	}

	struct testing_ctx ctx = {
		.out = stderr,
		.bench_time_ns = bench_time_ns,
		.bench_fixed_n = bench_fixed_n,
		.bench_count = bench_count,
	};
	/* Cases first: with no --run filter every case runs (inactive filter
	 * matches all); otherwise those whose name matches.  Benchmarks run only
	 * when --bench is given (bench_f is active only then). */
	for (const struct testing_suite *e = suite; e->name != NULL; e++) {
		if (e->kind == TESTING_CASE && filter_match(&run_f, e->name)) {
			run_case(&ctx, e);
		}
	}
	if (bench_f.active) {
		for (const struct testing_suite *e = suite; e->name != NULL;
		     e++) {
			if (e->kind == TESTING_BENCH &&
			    filter_match(&bench_f, e->name)) {
				run_bench(&ctx, e);
			}
		}
	}

	filter_free(&run_f);
	filter_free(&bench_f);

	if ((run != NULL || bench != NULL) &&
	    ctx.passed + ctx.failed + ctx.skipped + ctx.benched == 0) {
		(void)fprintf(stderr, "testing: no entries matched\n");
	}
	(void)fprintf(
		ctx.out,
		"=== DONE  %d passed, %d failed, %d skipped, %d benched\n",
		ctx.passed, ctx.failed, ctx.skipped, ctx.benched);
	(void)fflush(ctx.out);
	return T_RESULT(ctx) ? EXIT_SUCCESS : EXIT_FAILURE;
}
