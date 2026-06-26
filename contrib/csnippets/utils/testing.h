/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * testing.h - lightweight, header-only unit test framework
 *
 * OVERVIEW
 *   All test state is kept in a local `struct testing_ctx` variable declared
 *   inside main().  There are no global variables or external-linkage
 *   symbols.
 *
 * TEST CASE DEFINITION
 *   Use T_DECLARE_CASE(name) to begin a static test function definition.
 *   The macro expands to a static function with a hidden parameter
 *   `struct testing_ctx *_t_`.  All macros that read or modify per-case
 *   state (T_FAIL, T_FAILNOW, T_SKIP, T_SKIPNOW, T_FATAL, T_FATALF,
 *   T_IS_FAILED, T_IS_SKIPPED, and all T_EXPECT*) implicitly use this
 *   parameter.
 *
 *     T_DECLARE_CASE(test_add)
 *     {
 *         T_EXPECT_EQ(1 + 1, 2);
 *         T_EXPECT_TRUE(3 > 0);
 *     }
 *
 * SUBCASE FUNCTIONS
 *   A parameterised helper that uses testing macros should be declared with
 *   T_DECLARE_SUBCASE rather than manually writing `struct testing_ctx *_t_`.
 *   T_CALL_SUBCASE forwards the implicit `_t_` automatically:
 *
 *     T_DECLARE_SUBCASE(check_range, int v, int lo, int hi)
 *     {
 *         T_EXPECT(v >= lo && v <= hi);
 *     }
 *
 *     T_DECLARE_CASE(test_range)
 *     {
 *         T_CALL_SUBCASE(check_range, 5, 1, 10);
 *     }
 *
 * RUNNING TESTS
 *   In main(), declare the context with T_DECLARE_CTX(ctx), run individual
 *   cases with T_RUN_CASE(ctx, name), and return with T_RESULT(ctx):
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 *         T_RUN_CASE(t, test_add);
 *         T_RUN_CASE(t, test_range);
 *         return T_RESULT(t);
 *     }
 *
 *   To batch-run cases with an X-macro list, define the list in the test
 *   file itself and expand it with T_RUN_CASE:
 *
 *     #define ALL_TESTS(X) X(test_add) X(test_range)
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 * #define RUN(name) T_RUN_CASE(t, name)
 *         ALL_TESTS(RUN)
 * #undef RUN
 *         return T_RESULT(t);
 *     }
 *
 * DEFAULT MAIN (testing_main)
 *   testing_main() (defined in testing.c) is a ready-made entry point.  Pass it
 *   a NUL-terminated array of `struct testing_suite` entries built with T_CASE
 *   and T_BENCH and terminated with T_SUITE_END:
 *
 *     static const struct testing_suite suite[] = {
 *         T_CASE(test_add),
 *         T_CASE(test_range),
 *         T_BENCH(bench_add),
 *         T_SUITE_END,
 *     };
 *
 *     int main(int argc, char **argv)
 *     {
 *         return testing_main(argc, argv, suite);
 *     }
 *
 *   With no filter it runs every case and skips all benches.  A POSIX extended
 *   regular expression - given as `--run <ere>` (or the TESTING_FILTER
 *   environment variable when --run is absent) - selects entries by name
 *   (unanchored substring match): matching cases run first, then matching
 *   benches run last.  It returns EXIT_SUCCESS when no case failed.
 *
 * CASE OUTCOMES
 *   Each case has one of three outcomes printed by T_RUN_CASE:
 *     [PASS]  normal return, not marked failed or skipped.
 *     [FAIL]  T_FAIL or T_FAILNOW was called (takes priority over skipped).
 *     [SKIP]  T_SKIP or T_SKIPNOW was called, and the case was not marked
 *             failed.
 *
 *   T_FAILNOW and T_SKIPNOW abort the current case body immediately via
 *   longjmp back to T_RUN_CASE.  They must only be called within a test
 *   case body (i.e. under an active T_RUN_CASE).
 *
 * BENCH CASE DEFINITION
 *   Use T_DECLARE_BENCH(name) to begin a static benchmark function.
 *   The macro expands to a static function with a hidden parameter
 *   `struct testing_bench *_b_`.  The body must run the benchmarked
 *   operation exactly _b_->N times.
 *
 *     T_DECLARE_BENCH(bench_add)
 *     {
 *         for (uint_fast64_t i = 0; i < _b_->N; i++) {
 *             (void)add(1, 2);
 *         }
 *     }
 *
 * RUNNING BENCHMARKS
 *   Use T_RUN_BENCH(ctx, name) to run a benchmark.  It auto-calibrates the
 *   iteration count by doubling N each round until at least 1 second of
 *   wall time has elapsed, then reports the result as ns/op:
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 *         T_RUN_CASE(t, test_add);
 *         T_RUN_BENCH(t, bench_add);
 *         return T_RESULT(t);
 *     }
 *
 *   T_DECLARE_BENCH is always available.  The inline T_RUN_BENCH macro requires
 *   measure.h to be included before testing.h (it expands clock_monotonic_ns()
 *   directly); testing_main() runs benches without that include, since the
 *   timing lives in testing.c.  Benchmarks do not affect the
 *   passed/failed/skipped counters; the benched counter in struct testing_ctx
 *   is incremented instead.
 */

#ifndef UTILS_TESTING_H
#define UTILS_TESTING_H

#include <inttypes.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test execution context.  Declare one locally in main() with T_DECLARE_CTX. */
struct testing_ctx {
	FILE *out;
	int passed;
	int failed;
	int skipped;
	int benched;
	const char *current;
	volatile bool case_failed : 1;
	volatile bool case_skipped : 1;
	jmp_buf case_jmp;
};

/*
 * Benchmark context.  Passed via the implicit `_b_` parameter inside a
 * T_DECLARE_BENCH body, whose loop must run the benchmarked operation exactly
 * `_b_->N` times.
 */
struct testing_bench {
	uint_fast64_t N;
};

/*
 * T_DECLARE_CTX(ctx)
 *   Declares and zero-initialises a local `struct testing_ctx` named `ctx` in
 *   the current scope.  Must appear before T_RUN_CASE or T_RESULT.
 */
#define T_DECLARE_CTX(ctx_) struct testing_ctx ctx_ = { .out = stderr }

/*
 * T_DECLARE_CASE(name)
 *   Begins the definition of a static test function named `name`.
 *   Expands to: static void _testcase_name_(struct testing_ctx *_t_)
 *   The body follows immediately as a braced block.
 */
#define T_DECLARE_CASE(name_)                                                  \
	static void _testcase_##name_##_(struct testing_ctx *_t_)

/*
 * T_DECLARE_SUBCASE(name, type arg, ...)
 *   Declares a static parameterised helper that injects `_t_` as its first
 *   parameter.  Call it with T_CALL_SUBCASE.  All testing macros are usable
 *   inside the body.
 *   Expands to:
 *     static void _testsubcase_name_(struct testing_ctx *_t_, type arg, ...)
 */
#define T_DECLARE_SUBCASE(name_, ...)                                          \
	static void _testsubcase_##name_##_(                                   \
		struct testing_ctx *_t_, __VA_ARGS__)

/*
 * T_CALL_SUBCASE(name, arg, ...)
 *   Calls the subcase `name` declared with T_DECLARE_SUBCASE, forwarding
 *   the implicit `_t_` from the enclosing function automatically.
 *   Must be called from a function with `_t_` in scope.
 */
#define T_CALL_SUBCASE(name_, ...) (_testsubcase_##name_##_(_t_, __VA_ARGS__))

/*
 * T_RUN_CASE(ctx, name)
 *   Calls test function `name` with &ctx as _t_.
 *   Increments the corresponding counter in ctx.  A failed result takes
 *   priority over a skipped result.
 */
#define T_RUN_CASE(ctx_, name_)                                                \
	do {                                                                   \
		(ctx_).current = #name_;                                       \
		(ctx_).case_failed = false;                                    \
		(ctx_).case_skipped = false;                                   \
		(void)fprintf((ctx_).out, "=== RUN   %s\n", #name_);           \
		(void)fflush((ctx_).out);                                      \
		if (setjmp((ctx_).case_jmp) == 0) {                            \
			_testcase_##name_##_(&(ctx_));                         \
		}                                                              \
		if ((ctx_).case_failed) {                                      \
			(ctx_).failed++;                                       \
			(void)fprintf((ctx_).out, "--- FAIL  %s\n", #name_);   \
		} else if ((ctx_).case_skipped) {                              \
			(ctx_).skipped++;                                      \
			(void)fprintf((ctx_).out, "--- SKIP  %s\n", #name_);   \
		} else {                                                       \
			(ctx_).passed++;                                       \
			(void)fprintf((ctx_).out, "--- PASS  %s\n", #name_);   \
		}                                                              \
		(void)fflush((ctx_).out);                                      \
	} while (0)

/*
 * T_RESULT(ctx)
 *   Evaluates to true when ctx recorded no failures, false otherwise.
 *   Intended for boolean success checks.
 */
#define T_RESULT(ctx_) ((ctx_).failed == 0)

/* -------------------------------------------------------------------------
 * Benchmark case definition - always available.  Actually running a benchmark
 * requires a monotonic clock, provided either by T_RUN_BENCH (needs measure.h,
 * see the bottom of this header) or by testing_main (see testing.c).
 * ---------------------------------------------------------------------- */

/*
 * T_DECLARE_BENCH(name)
 *   Begins the definition of a static benchmark function named `name`.
 *   Expands to: static void _benchcase_name_(struct testing_bench *_b_)
 *   The body must run the benchmarked operation exactly _b_->N times.
 */
#define T_DECLARE_BENCH(name_)                                                 \
	static void _benchcase_##name_##_(struct testing_bench *_b_)

/* -------------------------------------------------------------------------
 * Test suite - a NUL-terminated array of cases and benches consumed by
 * testing_main().  Build entries with T_CASE / T_BENCH and terminate with
 * T_SUITE_END:
 *
 *     static const struct testing_suite suite[] = {
 *         T_CASE(test_add), T_BENCH(bench_add), T_SUITE_END,
 *     };
 * ---------------------------------------------------------------------- */

/* Whether a suite entry is a test case or a benchmark. */
enum testing_kind {
	TESTING_CASE,
	TESTING_BENCH,
};

/* One entry of a suite array.  The active `fn` member is selected by `kind`. */
struct testing_suite {
	const char *name;
	enum testing_kind kind;
	union {
		void (*test)(struct testing_ctx *);
		void (*bench)(struct testing_bench *);
	} fn;
};

/*
 * T_CASE(name) / T_BENCH(name)
 *   Build a struct testing_suite entry referring to a case declared with
 *   T_DECLARE_CASE or a benchmark declared with T_DECLARE_BENCH.
 * T_SUITE_END
 *   The required terminating entry (name == NULL).
 */
#define T_CASE(name_)                                                          \
	{                                                                      \
		.name = #name_, .kind = TESTING_CASE,                          \
		.fn = {.test = _testcase_##name_##_ }                          \
	}
#define T_BENCH(name_)                                                         \
	{                                                                      \
		.name = #name_, .kind = TESTING_BENCH,                         \
		.fn = {.bench = _benchcase_##name_##_ }                        \
	}
#define T_SUITE_END                                                            \
	{                                                                      \
		0                                                              \
	}

/*
 * testing_main(argc, argv, suite)
 *   Default test entry point.  Runs the NUL-terminated `suite`:
 *     - with no filter, every case runs and benches are skipped;
 *     - with a filter (the `--run <ere>` option, or the TESTING_FILTER
 *       environment variable when --run is absent), cases whose name matches
 *       run first, then matching benches run last.
 *   The filter is a POSIX extended regular expression matched as an unanchored
 *   substring.  Returns EXIT_SUCCESS when no case failed, else EXIT_FAILURE;
 *   a usage error or an invalid regex also returns EXIT_FAILURE.
 */
int testing_main(int argc, char *const *argv, const struct testing_suite *suite);

/* -------------------------------------------------------------------------
 * Logging macros - print a message to out with file and line number.
 * Do not affect pass/fail counters.  Usable anywhere.
 * ---------------------------------------------------------------------- */

#define T_LOGF(fmt, ...)                                                       \
	do {                                                                   \
		(void)fprintf(                                                 \
			(_t_)->out, "    %s:%d " fmt "\n", __FILE__, __LINE__, \
			__VA_ARGS__);                                          \
		(void)fflush((_t_)->out);                                      \
	} while (0)
#define T_LOG(msg) T_LOGF("%s", msg)

/* -------------------------------------------------------------------------
 * Fatal check - abort immediately if `cond` is false.  Use when continued
 * execution after a failed invariant would be unsafe or meaningless.
 * ---------------------------------------------------------------------- */

#define T_CHECK(cond_)                                                         \
	do {                                                                   \
		if (!(cond_)) {                                                \
			(void)fprintf(                                         \
				stderr,                                        \
				"    %s:%d runtime check failed: %s\n",        \
				__FILE__, __LINE__, #cond_);                   \
			(void)fflush(stderr);                                  \
			abort();                                               \
		}                                                              \
	} while (0)

/* -------------------------------------------------------------------------
 * Failure / skip macros - require `struct testing_ctx *_t_` in scope.
 *
 * T_FAIL()    Mark the current case as failed; continue execution.
 * T_FAILNOW() Mark the current case as failed; abort the case immediately.
 * T_SKIP()    Mark the current case as skipped; continue execution.
 * T_SKIPNOW() Mark the current case as skipped; abort the case immediately.
 *
 * T_FAILNOW() and T_SKIPNOW() use longjmp and must only be called inside a
 * case body running under T_RUN_CASE.  A failed result takes priority over
 * a skipped result.
 * ---------------------------------------------------------------------- */

#define T_FAIL()                                                               \
	do {                                                                   \
		(_t_)->case_failed = true;                                     \
	} while (0)
#define T_FAILNOW()                                                            \
	do {                                                                   \
		(_t_)->case_failed = true;                                     \
		longjmp((_t_)->case_jmp, 1);                                   \
	} while (0)

#define T_SKIP()                                                               \
	do {                                                                   \
		(_t_)->case_skipped = true;                                    \
	} while (0)
#define T_SKIPNOW()                                                            \
	do {                                                                   \
		(_t_)->case_skipped = true;                                    \
		longjmp((_t_)->case_jmp, 1);                                   \
	} while (0)

/* -------------------------------------------------------------------------
 * State query macros - evaluate to non-zero when the current case has been
 * marked in the corresponding state.
 * ---------------------------------------------------------------------- */

#define T_IS_FAILED() ((_t_)->case_failed)
#define T_IS_SKIPPED() ((_t_)->case_skipped)

/* -------------------------------------------------------------------------
 * Fatal log macros - print a message then abort the case immediately.
 * Equivalent to T_LOG/T_LOGF followed by T_FAILNOW.
 * ---------------------------------------------------------------------- */

#define T_FATALF(fmt_, ...)                                                    \
	do {                                                                   \
		T_LOGF(fmt_, __VA_ARGS__);                                     \
		T_FAILNOW();                                                   \
	} while (0)
#define T_FATAL(msg_) T_FATALF("%s", msg_)

/* -------------------------------------------------------------------------
 * Assertion macros - require `struct testing_ctx *_t_` in scope.
 * On failure each macro logs a diagnostic then calls T_FAILNOW.
 *
 * T_EXPECT(condition)             fail if condition is false
 * T_EXPECT_EQ(value, expect)      fail if value != expect
 * T_EXPECT_STREQ(value, expect)   fail if strcmp(value, expect) != 0
 * T_EXPECT_MEMEQ(value, expect, size)  fail if memcmp differs
 * ---------------------------------------------------------------------- */

#define T_EXPECT(condition_)                                                   \
	do {                                                                   \
		if (!(condition_)) {                                           \
			T_FATALF("expect failed: %s", #condition_);            \
		}                                                              \
	} while (0)

/* Private helpers for T_EXPECT_EQ type-generic formatting. */
#define T_EQ_FMT_(typ_)                                                        \
	_Generic(                                                              \
		(typ_),                                                        \
		signed char: "expect %jd, got %jd",                            \
		signed short: "expect %jd, got %jd",                           \
		signed int: "expect %jd, got %jd",                             \
		signed long: "expect %jd, got %jd",                            \
		signed long long: "expect %jd, got %jd",                       \
		unsigned char: "expect %ju, got %ju",                          \
		unsigned short: "expect %ju, got %ju",                         \
		unsigned int: "expect %ju, got %ju",                           \
		unsigned long: "expect %ju, got %ju",                          \
		unsigned long long: "expect %ju, got %ju",                     \
		default: "expect 0x%" PRIxPTR ", got 0x%" PRIxPTR)

#define T_EQ_CAST_(v_, typ_)                                                   \
	_Generic(                                                              \
		(typ_),                                                        \
		signed char: (intmax_t)(v_),                                   \
		signed short: (intmax_t)(v_),                                  \
		signed int: (intmax_t)(v_),                                    \
		signed long: (intmax_t)(v_),                                   \
		signed long long: (intmax_t)(v_),                              \
		unsigned char: (uintmax_t)(v_),                                \
		unsigned short: (uintmax_t)(v_),                               \
		unsigned int: (uintmax_t)(v_),                                 \
		unsigned long: (uintmax_t)(v_),                                \
		unsigned long long: (uintmax_t)(v_),                           \
		default: (uintptr_t)(v_))

#define T_EXPECT_EQ(value_, expect_)                                           \
	do {                                                                   \
		if ((value_) != (expect_)) {                                   \
			(void)fprintf(                                         \
				(_t_)->out, "    %s:%d ", __FILE__, __LINE__); \
			(void)fprintf(                                         \
				(_t_)->out, T_EQ_FMT_(value_),                 \
				T_EQ_CAST_(expect_, value_),                   \
				T_EQ_CAST_(value_, value_));                   \
			(void)fprintf((_t_)->out, "\n");                       \
			(void)fflush((_t_)->out);                              \
			T_FAILNOW();                                           \
		}                                                              \
	} while (0)

#define T_EXPECT_STREQ(value_, expect_)                                        \
	do {                                                                   \
		if (strcmp((value_), (expect_)) != 0) {                        \
			T_FATALF(                                              \
				"expect \"%s\", got \"%s\"", (expect_),        \
				(value_));                                     \
		}                                                              \
	} while (0)

#define T_EXPECT_MEMEQ(value_, expect_, size_)                                 \
	do {                                                                   \
		if (memcmp((value_), (expect_), (size_)) != 0) {               \
			T_FATALF(                                              \
				"memory mismatch: %zu bytes differ",           \
				(size_t)(size_));                              \
		}                                                              \
	} while (0)

/* -------------------------------------------------------------------------
 * Inline benchmark runner - available only when measure.h is included before
 * testing.h, since T_RUN_BENCH expands clock_monotonic_ns() directly.  For a
 * runner that does not need measure.h in the test file, see testing_main().
 * ---------------------------------------------------------------------- */

#ifdef UTILS_MEASURE_H

/*
 * T_RUN_BENCH(ctx, name)
 *   Runs benchmark `name`, auto-calibrating by doubling N each round until
 *   at least 1 second of wall time has elapsed.  Reports the result as
 *   ns/op and increments ctx.benched.  Does not affect passed/failed/skipped.
 */
#define T_RUN_BENCH(ctx_, name_)                                               \
	do {                                                                   \
		(void)fprintf((ctx_).out, "=== RUN   %s\n", #name_);           \
		(void)fflush((ctx_).out);                                      \
		struct testing_bench _b_ = { 0 };                              \
		const int_least64_t _bstart_ = clock_monotonic_ns();           \
		int_least64_t _belapsed_;                                      \
		uint_fast64_t _bN_ = 1;                                        \
		do {                                                           \
			_b_.N = _bN_;                                          \
			_benchcase_##name_##_(&_b_);                           \
			_bN_ <<= 1u;                                           \
			_belapsed_ = clock_monotonic_ns() - _bstart_;          \
		} while (_bN_ && _belapsed_ < 1000000000 /* 1s */);            \
		const double _bnsop_ =                                         \
			(double)_belapsed_ / (double)(_bN_ - 1);               \
		(void)fprintf(                                                 \
			(ctx_).out, "--- BENCH %s\t%ju\t%.2f ns/op\n", #name_, \
			(uintmax_t)(_bN_ - 1), _bnsop_);                       \
		(void)fflush((ctx_).out);                                      \
		(ctx_).benched++;                                              \
	} while (0)

#endif /* UTILS_MEASURE_H */

#endif /* UTILS_TESTING_H */
