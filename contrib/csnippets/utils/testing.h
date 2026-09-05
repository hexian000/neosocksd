/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * testing.h - lightweight unit test framework
 *
 * OVERVIEW
 *   Case state is kept in a local `struct testing_ctx` variable declared inside
 *   main().  The case macros and assertion helpers are header-only.  `T_KEEP`,
 *   `T_RUN_BENCH`, `testing_main`, and the benchmark timer helpers use external
 *   definitions in testing.c; link the `testing` library when using them.
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
 *         T_EXPECT(3 > 0);
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
 * PER-CASE CLEANUP
 *   State a case leaves behind outlives it: every case in a binary runs in one
 *   process, and T_FAILNOW / T_SKIPNOW abandon the body wherever they are
 *   called, skipping whatever the body meant to undo at its end.  That is
 *   harmless for the case's own locals, which the longjmp unwinds past, and not
 *   harmless for anything file-static a case arms on the code under test - a
 *   -Wl,--wrap fault injector, a test double told what to answer - which the
 *   next case would then run against.
 *
 *   Register the undo with T_CLEANUP(fn, data) at the point of the setup, and
 *   the runner calls fn(data) when the case ends however it ends.  Cleanups run
 *   in reverse order of registration, before the outcome is reported:
 *
 *     T_DECLARE_CASE(test_alloc_failure)
 *     {
 *         fail_malloc_of = sizeof(struct thing);
 *         T_CLEANUP(clear_fail_malloc, NULL);
 *         T_EXPECT_EQ(thing_new(), NULL);   // safe to end the case here
 *     }
 *
 * RUNNING TESTS
 *   In main(), declare the context with T_DECLARE_CTX(ctx) and run individual
 *   cases with T_RUN_CASE(ctx, name).  T_RESULT(ctx) is a boolean, not an exit
 *   status, so map it onto EXIT_SUCCESS / EXIT_FAILURE; returning it directly
 *   would report a passing suite as a failure and a failing one as a success:
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 *         T_RUN_CASE(t, test_add);
 *         T_RUN_CASE(t, test_range);
 *         return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
 *     }
 *
 *   To batch-run cases with an X-macro list, define the list in the test
 *   file itself and expand it with T_RUN_CASE.  The list juxtaposes its
 *   expansions with nothing in between, so the per-entry macro has to carry
 *   the statement terminator:
 *
 *     #define ALL_TESTS(X) X(test_add) X(test_range)
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 * #define RUN(name) T_RUN_CASE(t, name);
 *         ALL_TESTS(RUN)
 * #undef RUN
 *         return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
 *     }
 *
 * DEFAULT MAIN (testing_main)
 *   testing_main() (defined in testing.c) is a ready-made entry point.  Pass it
 *   a NULL-terminated array of `struct testing_suite` entries built with T_CASE
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
 *   Command-line flags (Go-like):
 *     --run <ere>     run the test cases whose name matches; with no --run
 *                     every case runs.  Falls back to the TESTING_FILTER
 *                     environment variable when absent.
 *     --bench <ere>   run the benchmarks whose name matches; with no --bench
 *                     no benchmark runs (TESTING_BENCH is the env fallback).
 *     --benchtime <d> per-benchmark wall-clock budget, e.g. 500ms, 2s, 1m
 *                     (bare number means seconds); or "<n>x" to run a fixed
 *                     count once instead of timing (e.g. 1x for a quick smoke).
 *     --count <n>     repeat each benchmark n times, reporting the minimum
 *                     ns/op (min-of-n).
 *   The pattern is a POSIX extended regular expression matched as an unanchored
 *   substring; where POSIX regex is unavailable it degrades to a literal
 *   substring.  Matching cases run first, then matching benches.  Each filter
 *   that selects nothing is reported separately on stderr, which is a warning,
 *   not an error.  Returns EXIT_SUCCESS when no case failed (and no benchmark
 *   was optimized away).
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
 *   case body (i.e. under an active T_RUN_CASE).  The cleanups the case
 *   registered still run, and still before the outcome is decided, so one that
 *   calls T_FAIL turns the case it cleaned up after into a failure.
 *
 * BENCH CASE DEFINITION
 *   Use T_DECLARE_BENCH(name) to begin a static benchmark function with a
 *   hidden parameter `struct testing_bench *_b_`.  The body runs the benchmarked
 *   operation _b_->N times; write the loop with T_BENCH_LOOP() and wrap the
 *   result in T_KEEP() so the optimizer cannot delete it (see those macros):
 *
 *     T_DECLARE_BENCH(bench_add)
 *     {
 *         T_BENCH_LOOP() {
 *             T_KEEP(add(1, 2));
 *         }
 *     }
 *
 *   Optional extras: T_BENCH_SET_BYTES for a throughput column, T_BENCH_MALLOC
 *   and friends for B/op and allocs/op, and T_BENCH_RESET_TIMER / STOP / START
 *   to exclude setup from the timing.
 *
 * RUNNING BENCHMARKS
 *   Use T_RUN_BENCH(ctx, name) to run a benchmark.  It auto-calibrates the
 *   iteration count by doubling N each round until at least 1 second of active
 *   time has elapsed, then reports per-op time, per-op heap use and allocations
 *   in aligned columns, e.g.:
 *
 *     --- BENCH bench_add        73400320     13.6ns/op          0/op  0 allocs/op
 *
 *   Times and byte counts are rendered with strings/format.h (SI-prefixed
 *   durations like 13.6ns/op, IEC byte counts like 1.50KiB/op), so the runner
 *   pulls in libm.  Memory columns are zero unless the benchmark reports
 *   allocations; a throughput column (e.g. 2.33GB/s) appears only when the
 *   benchmark calls T_BENCH_SET_BYTES.  If the benchmarked work is optimized
 *   away (no T_KEEP), the runner reports a hard failure instead of a bogus
 *   number.  testing_main accepts --benchtime and --count to tune the budget
 *   and report the minimum of repeated runs.
 *
 *     int main(void)
 *     {
 *         T_DECLARE_CTX(t);
 *         T_RUN_CASE(t, test_add);
 *         T_RUN_BENCH(t, bench_add);
 *         return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
 *     }
 *
 *   T_DECLARE_BENCH and T_RUN_BENCH are always available; the monotonic clock
 *   lives in testing.c, so test files need not include measure.h.  testing_main()
 *   runs benches the same way.  Benchmarks do not affect the passed/failed/
 *   skipped counters; the benched counter in struct testing_ctx is incremented
 *   instead (an optimized-away benchmark counts as a failure).
 */

#ifndef UTILS_TESTING_H
#define UTILS_TESTING_H

#include "os/clock.h"

#include <float.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * One undo registered by the running case with T_CLEANUP: `fn` is called with
 * `data` once the case ends.  See the PER-CASE CLEANUP overview.
 */
struct testing_cleanup {
	void (*fn)(void *data);
	void *data;
};

/*
 * How many cleanups one case may have registered at a time.  Overflowing it is
 * a runtime check failure rather than a dropped entry: dropping one would leave
 * behind exactly the state T_CLEANUP exists to restore.
 */
enum { T_CLEANUP_MAX = 16 };

/* Test execution context.  Declare one locally in main() with T_DECLARE_CTX. */
struct testing_ctx {
	FILE *out;
	int passed;
	int failed;
	int skipped;
	int benched;
	volatile bool case_failed : 1;
	volatile bool case_skipped : 1;
	jmp_buf case_jmp;
	/* Cleanups the current case has registered but not yet run; the runner
	 * empties this between cases, so it never carries state across one. */
	struct testing_cleanup cleanups[T_CLEANUP_MAX];
	int cleanup_count;
	/*
	 * Benchmark tuning, set by testing_main from CLI flags; zero selects the
	 * default, so a T_DECLARE_CTX context needs no extra setup.
	 *   bench_time_ns  min active time per run (--benchtime <dur>); default 1s
	 *   bench_fixed_n  exact iters/run, untimed (--benchtime Nx); 0 = timed
	 *   bench_count    repeats, reporting the minimum ns/op (--count); default 1
	 */
	int_fast64_t bench_time_ns;
	uint_fast64_t bench_fixed_n;
	int bench_count;
};

/*
 * Benchmark context.  Passed via the implicit `_b_` parameter inside a
 * T_DECLARE_BENCH body, whose loop must run the benchmarked operation exactly
 * `_b_->N` times.
 *
 * `bytes` and `allocs` are running totals reported by the benchmark (see
 * T_BENCH_MALLOC and friends).  `bytes` is the heap memory requested; `allocs`
 * counts successful malloc/calloc/realloc/aligned_alloc calls and every free,
 * since in C a free is itself a call worth measuring.  The runner divides these
 * counts by the total iteration count to print `B/op` and `allocs/op`, in the
 * spirit of Go's `-benchmem`.  They accumulate across calibration rounds,
 * exactly like the elapsed time used for per-op timing, so the figures stay
 * correct.
 *
 * `set_bytes` is the number of bytes processed by a single operation, set with
 * T_BENCH_SET_BYTES (like Go's b.SetBytes).  When non-zero the runner adds a
 * throughput column.  Unlike `bytes`/`allocs` it is a per-op value, not a
 * running total.
 */
struct testing_bench {
	uint_fast64_t N;
	uint_fast64_t bytes;
	uint_fast64_t allocs;
	uint_fast64_t set_bytes;
	/*
	 * Internal timer state for T_BENCH_RESET_TIMER / STOP / START.  Managed by
	 * the runner and those helpers; benchmark bodies must not touch it.
	 */
	int_fast64_t round_start; /* monotonic ns at round start or last reset */
	int_fast64_t paused_ns; /* time excluded while the timer was stopped */
	int_fast64_t pause_at; /* monotonic ns when stopped, -1 while running */
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
 *   Expands to: static void testcase_name_(struct testing_ctx *_t_)
 *   The body follows immediately as a braced block.
 */
#define T_DECLARE_CASE(name_)                                                  \
	static void testcase_##name_##_(struct testing_ctx *_t_)

/*
 * T_DECLARE_SUBCASE(name, type arg, ...)
 *   Declares a static parameterised helper that injects `_t_` as its first
 *   parameter.  Call it with T_CALL_SUBCASE.  All testing macros are usable
 *   inside the body.
 *   Expands to:
 *     static void testsubcase_name_(struct testing_ctx *_t_, type arg, ...)
 */
#define T_DECLARE_SUBCASE(name_, ...)                                          \
	static void testsubcase_##name_##_(struct testing_ctx *_t_, __VA_ARGS__)

/*
 * T_CALL_SUBCASE(name, arg, ...)
 *   Calls the subcase `name` declared with T_DECLARE_SUBCASE, forwarding
 *   the implicit `_t_` from the enclosing function automatically.
 *   Must be called from a function with `_t_` in scope.
 */
#define T_CALL_SUBCASE(name_, ...) (testsubcase_##name_##_(_t_, __VA_ARGS__))

/*
 * Run what the case registered with T_CLEANUP (see testing_cleanup_push_),
 * most recent first, and leave the list empty.  Each cleanup gets a setjmp
 * guard of its own, so one that ends itself with T_FAILNOW or a failing
 * expectation abandons only itself and the cleanups registered before it still
 * run; a cleanup that registers another has it run in turn.
 */
static inline void testing_run_cleanups_(struct testing_ctx *t)
{
	while (t->cleanup_count > 0) {
		t->cleanup_count--;
		if (setjmp(t->case_jmp) == 0) {
			const struct testing_cleanup c =
				t->cleanups[t->cleanup_count];
			c.fn(c.data);
		}
	}
}

/*
 * Announce `name`, run `test` under a setjmp guard so T_FAILNOW / T_SKIPNOW can
 * abort the body, run the case's cleanups, then report and count the outcome.
 * Backs both T_RUN_CASE and testing_main's runner, so the two cannot drift
 * apart; being static inline it keeps the macro path free of any link
 * dependency.  The cleanups run before the outcome is read, so one of them can
 * still fail the case, and the case starts with none left over from the last.
 */
static inline void testing_run_case_(
	struct testing_ctx *t, const char *name,
	void (*test)(struct testing_ctx *))
{
	t->case_failed = false;
	t->case_skipped = false;
	t->cleanup_count = 0;
	(void)fprintf(t->out, "=== RUN   %s\n", name);
	(void)fflush(t->out);
	if (setjmp(t->case_jmp) == 0) {
		test(t);
	}
	testing_run_cleanups_(t);
	if (t->case_failed) {
		t->failed++;
		(void)fprintf(t->out, "--- FAIL  %s\n", name);
	} else if (t->case_skipped) {
		t->skipped++;
		(void)fprintf(t->out, "--- SKIP  %s\n", name);
	} else {
		t->passed++;
		(void)fprintf(t->out, "--- PASS  %s\n", name);
	}
	(void)fflush(t->out);
}

/*
 * T_RUN_CASE(ctx, name)
 *   Calls test function `name` with &ctx as _t_.
 *   Increments the corresponding counter in ctx.  A failed result takes
 *   priority over a skipped result.
 */
#define T_RUN_CASE(ctx_, name_)                                                \
	(testing_run_case_(&(ctx_), #name_, testcase_##name_##_))

/*
 * T_RESULT(ctx)
 *   Evaluates to true when ctx recorded no failures, false otherwise.
 *   Intended for boolean success checks: it is the inverse of an exit status,
 *   so main() must return T_RESULT(ctx) ? EXIT_SUCCESS : EXIT_FAILURE and
 *   never T_RESULT(ctx) itself.
 */
#define T_RESULT(ctx_) ((ctx_).failed == 0)

/*
 * TESTING_PROMOTE_(value)
 *   The dispatch key of a _Generic on `value`, for T_KEEP and T_EXPECT_EQ.
 *   A generic selection matches the controlling expression's own type and
 *   promotes nothing (C11 6.5.1.1), while a bit-field has the integer type of
 *   its width (6.7.2.1p10), which no type name spells: every association misses
 *   it and the selection takes the default one.  GCC does exactly that, typing
 *   such an operand `unsigned char:3`; clang matches the declared type instead,
 *   and neither is wrong.  Pairing the operand with a null pointer constant in
 *   a conditional operator settles it: an arithmetic operand takes the usual
 *   arithmetic conversions' type (6.5.15p5, 6.3.1.8) and with it the integer
 *   promotions (6.3.1.1) - a bit-field arrives as `int`, as does every other
 *   narrow integer type - while a pointer operand keeps its own (6.5.15p6).  A
 *   bit-field of an implementation-defined wider type (`unsigned long long
 *   x : 40`) is outside the promotion rule and still needs a cast.  The
 *   controlling expression is unevaluated, so `value` is still evaluated once
 *   only, by the call the selection resolves to.
 */
#define TESTING_PROMOTE_(value_) (1 ? (value_) : 0)

/* -------------------------------------------------------------------------
 * Benchmark case definition.  Run a benchmark with T_RUN_BENCH or testing_main;
 * both rely on the monotonic clock that lives in testing.c.
 * ---------------------------------------------------------------------- */

/*
 * T_DECLARE_BENCH(name)
 *   Begins the definition of a static benchmark function named `name`.
 *   Expands to: static void benchcase_name_(struct testing_bench *_b_)
 *   The body must run the benchmarked operation exactly _b_->N times.
 */
#define T_DECLARE_BENCH(name_)                                                 \
	static void benchcase_##name_##_(struct testing_bench *_b_)

/*
 * T_BENCH_LOOP()
 *   The benchmark loop header, in the spirit of Go 1.24's `for b.Loop()`.  Use
 *   it instead of a hand-written `for (i = 0; i < _b_->N; i++)` so the
 *   iteration bound is never miswritten:
 *
 *     T_DECLARE_BENCH(bench_add)
 *     {
 *         T_BENCH_LOOP() {
 *             T_KEEP(add(1, 2));
 *         }
 *     }
 *
 *   Unlike Go's form it cannot keep the operation's result alive by itself
 *   (ISO C11 has no compiler barrier), so wrap the result in T_KEEP (below).
 *
 *   The bound is copied into the loop's own object: the runner fixes N before
 *   the call and no body may change it, but a body that calls an opaque
 *   function - which a benchmark almost always does - would otherwise reload
 *   `_b_->N` every round, since that call might write it.
 */
#define T_BENCH_LOOP()                                                         \
	for (uint_fast64_t _i_ = 0, _n_ = (_b_)->N; _i_ < _n_; _i_++)

/* -------------------------------------------------------------------------
 * Defeating dead-code elimination - pure ISO C11.
 *
 * A microbenchmark whose result is never used may be deleted outright by the
 * optimizer; the runner then doubles the iteration count until it overflows and
 * reports a hard failure (see testing_bench_run).  ISO C11 makes every access
 * to a `volatile` object an observable side effect the implementation may not
 * elide (5.1.2.3), so routing a value through a volatile sink forces the
 * computation behind it to be emitted - the portable equivalent of Google
 * Benchmark's DoNotOptimize, with no compiler-specific inline assembly.
 *
 *     T_DECLARE_BENCH(bench_hash)
 *     {
 *         uint32_t h = 0;
 *         T_BENCH_LOOP() {
 *             h = hash(data, len, h);  // feed the previous result back as the
 *         }                            // seed so the call cannot be hoisted
 *         T_KEEP(h);                   // consume the final result
 *     }
 *
 * T_KEEP accepts any standard arithmetic type or object-pointer value; its
 * only cost is one forced store.  It dispatches on the promoted operand type
 * (see TESTING_PROMOTE_), so a bit-field or an enum - compatible with whichever
 * integer type the implementation chose for it (6.7.2.2p4) - needs no cast.
 * Calling it once after the loop is enough when results accumulate into a
 * single variable.  To stop the optimizer hoisting a loop-invariant input out
 * of the loop, prefer feeding the loop index or the previous result as input,
 * as above.
 * ---------------------------------------------------------------------- */

/* volatile sinks backing T_KEEP; defined once in testing.c. */
extern volatile unsigned long long testing_keep_uint_;
extern volatile long double testing_keep_flt_;
extern const void *volatile testing_keep_ptr_;

static inline void testing_keep_u_(unsigned long long v)
{
	testing_keep_uint_ = v;
}
static inline void testing_keep_f_(long double v)
{
	testing_keep_flt_ = v;
}
static inline void testing_keep_p_(const volatile void *v)
{
	testing_keep_ptr_ = (const void *)v;
}

/*
 * T_KEEP(value)
 *   Force `value` - and the computation that produced it - to be evaluated,
 *   defeating dead-code elimination.  Accepts any standard arithmetic type or
 *   object pointer.  The _Generic selects a sink function from the promoted
 *   operand type; only the selected branch is applied to `value`, so the
 *   unselected branches need not type-check against it, and the value reaches
 *   the sink unpromoted, exactly as written.
 */
#define T_KEEP(value_)                                                         \
	(_Generic(                                                             \
		TESTING_PROMOTE_(value_),                                      \
		 float: testing_keep_f_,                                       \
		 double: testing_keep_f_,                                      \
		 long double: testing_keep_f_,                                 \
		 int: testing_keep_u_,                                         \
		 unsigned int: testing_keep_u_,                                \
		 long: testing_keep_u_,                                        \
		 unsigned long: testing_keep_u_,                               \
		 long long: testing_keep_u_,                                   \
		 unsigned long long: testing_keep_u_,                          \
		 default: testing_keep_p_)((value_)))

/* -------------------------------------------------------------------------
 * Benchmark memory reporting - opt-in, mirrors Go's `-benchmem`.
 *
 * C has no runtime that tracks allocations, so a benchmark must report them
 * itself.  The counting wrappers below stand in for the standard allocators
 * (malloc/calloc/realloc/aligned_alloc/free): allocation wrappers delegate to
 * the standard function first, then record successful allocations in the
 * implicit `_b_`.  Allocations add their requested size to `bytes`;
 * T_BENCH_FREE records every free call but adds no bytes.
 *
 *     T_DECLARE_BENCH(bench_dup)
 *     {
 *         T_BENCH_LOOP() {
 *             void *p = T_BENCH_MALLOC(64);
 *             T_BENCH_FREE(p);
 *         }
 *     }
 *
 * For a custom allocator, call T_BENCH_REPORT(nbytes) to record one allocator
 * call moving `nbytes` bytes - use 0 for a free.  Benchmarks that report nothing
 * print a zero memory column.  To add a throughput column, call
 * T_BENCH_SET_BYTES with the bytes processed per operation.
 * ---------------------------------------------------------------------- */

/* Record one allocator call moving `nbytes_` bytes into `_b_` (0 for a free). */
#define T_BENCH_REPORT(nbytes_)                                                \
	do {                                                                   \
		(_b_)->allocs++;                                               \
		(_b_)->bytes += (uint_fast64_t)(nbytes_);                      \
	} while (0)

/* Counting wrappers over the standard allocators; record into `b` on success. */
static inline void *testing_bench_malloc(struct testing_bench *b, size_t size)
{
	void *const p = malloc(size);
	if (p != NULL) {
		b->allocs++;
		b->bytes += size;
	}
	return p;
}

static inline void *
testing_bench_calloc(struct testing_bench *b, size_t nmemb, size_t size)
{
	void *const p = calloc(nmemb, size);
	if (p != NULL) {
		b->allocs++;
		b->bytes += (uint_fast64_t)nmemb * size;
	}
	return p;
}

static inline void *
testing_bench_realloc(struct testing_bench *b, void *ptr, size_t size)
{
	void *const p = realloc(ptr, size);
	if (p != NULL) {
		b->allocs++;
		b->bytes += size;
	}
	return p;
}

static inline void *testing_bench_aligned_alloc(
	struct testing_bench *b, size_t alignment, size_t size)
{
	void *const p = aligned_alloc(alignment, size);
	if (p != NULL) {
		b->allocs++;
		b->bytes += size;
	}
	return p;
}

/* Count one free as an allocator call (no bytes), then release `ptr`. */
static inline void testing_bench_free(struct testing_bench *b, void *ptr)
{
	b->allocs++;
	free(ptr);
}

/* Convenience macros injecting the implicit `_b_`, like the standard allocators. */
#define T_BENCH_MALLOC(size_) (testing_bench_malloc((_b_), (size_)))
#define T_BENCH_CALLOC(nmemb_, size_)                                          \
	(testing_bench_calloc((_b_), (nmemb_), (size_)))
#define T_BENCH_REALLOC(ptr_, size_)                                           \
	(testing_bench_realloc((_b_), (ptr_), (size_)))
#define T_BENCH_ALIGNED_ALLOC(alignment_, size_)                               \
	(testing_bench_aligned_alloc((_b_), (alignment_), (size_)))
#define T_BENCH_FREE(ptr_) (testing_bench_free((_b_), (ptr_)))

/*
 * T_BENCH_SET_BYTES(nbytes_)
 *   Declare that one operation processes `nbytes_` bytes (like Go's
 *   b.SetBytes).  The runner then prints a throughput column.  This is a per-op
 *   value; setting it repeatedly to the same number is harmless.
 */
#define T_BENCH_SET_BYTES(nbytes_)                                             \
	((void)((_b_)->set_bytes = (uint_fast64_t)(nbytes_)))

/* -------------------------------------------------------------------------
 * Benchmark timer control - mirrors Go's b.ResetTimer/StopTimer/StartTimer.
 *
 * The runner times the whole benchmark body.  Stop the timer around expensive
 * per-call setup to exclude it from the measurement, then start it again; or
 * reset it to discard everything timed so far (e.g. after one-time
 * initialisation).  These affect only the time measurement, not the
 * bytes/allocs counters.  The helpers live in testing.c so the monotonic clock
 * stays there and benchmark files need not include it.
 *
 *     T_DECLARE_BENCH(bench_lookup)
 *     {
 *         T_BENCH_STOP_TIMER();
 *         struct table *tbl = build_table();   // not measured
 *         T_BENCH_START_TIMER();
 *         T_BENCH_LOOP() {
 *             T_KEEP(lookup(tbl, key));
 *         }
 *     }
 * ---------------------------------------------------------------------- */
void testing_bench_reset_timer(struct testing_bench *b);
void testing_bench_stop_timer(struct testing_bench *b);
void testing_bench_start_timer(struct testing_bench *b);

#define T_BENCH_RESET_TIMER() (testing_bench_reset_timer(_b_))
#define T_BENCH_STOP_TIMER() (testing_bench_stop_timer(_b_))
#define T_BENCH_START_TIMER() (testing_bench_start_timer(_b_))

/*
 * T_BENCH_LOGF(fmt, ...) / T_BENCH_LOG(msg)
 *   Log a message from a benchmark body to stderr with file and line.  A bench
 *   has `_b_`, not the `_t_` that T_LOGF requires, so this is its counterpart.
 *   For hard assertions inside a benchmark, T_CHECK is also available.
 */
#define T_BENCH_LOGF(fmt_, ...)                                                \
	do {                                                                   \
		(void)fprintf(                                                 \
			stderr, "    %s:%d " fmt_ "\n", __FILE__, __LINE__,    \
			__VA_ARGS__);                                          \
		(void)fflush(stderr);                                          \
	} while (0)
#define T_BENCH_LOG(msg_) T_BENCH_LOGF("%s", msg_)

/* -------------------------------------------------------------------------
 * Test suite - a NULL-terminated array of cases and benches consumed by
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
		.fn = {.test = testcase_##name_##_ }                           \
	}
#define T_BENCH(name_)                                                         \
	{                                                                      \
		.name = #name_, .kind = TESTING_BENCH,                         \
		.fn = {.bench = benchcase_##name_##_ }                         \
	}
#define T_SUITE_END { 0 }

/*
 * testing_main(argc, argv, suite)
 *   Default test entry point.  Runs the NULL-terminated `suite`: cases selected
 *   by --run (all of them when --run is absent) run first, then benchmarks
 *   selected by --bench (none when --bench is absent) run last.  See the DEFAULT
 *   MAIN overview for the flags (--run, --bench, --benchtime, --count) and the
 *   TESTING_FILTER / TESTING_BENCH environment fallbacks.  The pattern is a
 *   POSIX extended regular expression (a literal substring where regex is
 *   unavailable), matched unanchored.  Returns EXIT_SUCCESS when no case failed
 *   and no benchmark was optimized away; a usage error or invalid regex returns
 *   EXIT_FAILURE.
 */
int testing_main(int argc, char *const *argv, const struct testing_suite *suite);

/*
 * testing_bench_run(ctx, name, bench)
 *   Runs benchmark function `bench` (reported under `name`), auto-calibrating by
 *   doubling N each round until at least ctx->bench_time_ns of active time has
 *   elapsed (default 1s), honoring ctx->bench_fixed_n and ctx->bench_count.
 *   Reports per-op time, per-op bytes/allocs and optional throughput (see the
 *   RUNNING BENCHMARKS notes), and increments ctx.benched; a benchmark whose
 *   work is optimized away is reported as a failure instead.  Backs the
 *   T_RUN_BENCH macro; the monotonic clock lives in testing.c so callers need
 *   not include measure.h.
 */
void testing_bench_run(
	struct testing_ctx *t, const char *name,
	void (*bench)(struct testing_bench *));

/*
 * T_RUN_BENCH(ctx, name)
 *   Runs benchmark `name` via testing_bench_run.  Always available; unlike the
 *   former inline form it does not require measure.h to be included first.
 */
#define T_RUN_BENCH(ctx_, name_)                                               \
	(testing_bench_run(&(ctx_), #name_, benchcase_##name_##_))

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

/* T_CHECK that a C11 <threads.h> call returned thrd_success. The using
 * translation unit must include <threads.h> for thrd_success. */
#define THRD_CHECK(expr) T_CHECK((expr) == thrd_success)

/* -------------------------------------------------------------------------
 * Per-case cleanup - requires `struct testing_ctx *_t_` in scope.
 *
 * T_CLEANUP(fn, data)
 *   Register `fn(data)` to run when the current case ends, whether it returns
 *   normally or is abandoned by T_FAILNOW / T_SKIPNOW / a failing expectation.
 *   Register it right where the state is set up, since a body that undoes it at
 *   its end undoes nothing when a fatal expectation ends the body first.
 *   Cleanups run most recent first (testing_run_cleanups_), before the outcome
 *   is reported, and a case may have at most T_CLEANUP_MAX of them registered.
 *   Use it for state that outlives the case - file-static fault injectors and
 *   test doubles, a temporary file, a thread to join - and not for the case's
 *   own locals, which need no undoing.
 *
 *   A cleanup may fail the case (T_FAIL, T_EXPECT and friends need `_t_`, so
 *   pass the context as `data` to reach them), and T_CLEANUP works the same in
 *   a T_DECLARE_SUBCASE body.  Benchmarks have no cleanups: T_CHECK is fatal to
 *   the whole binary, so nothing of a benchmark's survives into the next one.
 * ---------------------------------------------------------------------- */

static inline void
testing_cleanup_push_(struct testing_ctx *t, void (*fn)(void *), void *data)
{
	T_CHECK(fn != NULL);
	T_CHECK(t->cleanup_count < T_CLEANUP_MAX);
	t->cleanups[t->cleanup_count++] =
		(struct testing_cleanup){ .fn = fn, .data = data };
}

#define T_CLEANUP(fn_, data_) (testing_cleanup_push_(_t_, (fn_), (data_)))

/* -------------------------------------------------------------------------
 * Deadline helpers for bounded blocking waits (threaded suites).
 *
 * Reaching the deadline is a failure, not a tolerated outcome: the waits are
 * satisfied promptly when the code under test is correct, so a deadline only
 * ever fires on a real defect and keeps a regression from hanging CI instead of
 * reporting. The clock is the Unix wall clock (clock_unix, i.e. CLOCK_REALTIME
 * or the ISO C TIME_UTC fallback) so the result can drive cnd_timedwait
 * directly, which requires its own clock; do not substitute a monotonic clock.
 * ---------------------------------------------------------------------- */

enum { T_TIMEOUT_SECONDS = 10 };

static inline void t_deadline_set(struct timespec *restrict deadline)
{
	T_CHECK(clock_unix(deadline));
	deadline->tv_sec += T_TIMEOUT_SECONDS;
}

static inline bool t_deadline_expired(const struct timespec *restrict deadline)
{
	struct timespec now;
	T_CHECK(clock_unix(&now));
	return now.tv_sec > deadline->tv_sec ||
	       (now.tv_sec == deadline->tv_sec &&
		now.tv_nsec >= deadline->tv_nsec);
}

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
 * T_EXPECT_EQ(value, expect)      fail unless the two hold the same value
 *                                 (an exact comparison, not C's `==`)
 * T_EXPECT_STREQ(value, expect)   fail if strcmp(value, expect) != 0
 * T_EXPECT_MEMEQ(value, expect, size)  fail if memcmp differs
 * ---------------------------------------------------------------------- */

#define T_EXPECT(condition_)                                                   \
	do {                                                                   \
		if (!(condition_)) {                                           \
			T_FATALF("expect failed: %s", #condition_);            \
		}                                                              \
	} while (0)

/*
 * Compare and, on mismatch, report "expect X, got Y" to `out`.  Each variant
 * takes the widest natural type of the categories it serves -- intmax_t for
 * signed, uintmax_t for unsigned, long double for floating -- except _p_, which
 * takes `const void *`: every object pointer converts to it implicitly and that
 * conversion preserves equality, unlike the integer types.
 *
 * A signed and an unsigned operand are never folded into one category, because
 * neither direction is lossless: intmax_t cannot represent an unsigned value
 * above INTMAX_MAX, and uintmax_t cannot represent a negative one.  Such a pair
 * goes to _iu_ / _ui_, which keep each operand in its own type, compare the two
 * values exactly, and print each with its own conversion.
 *
 * That is deliberately not what C's `==` says about the same two operands: `==`
 * applies the usual arithmetic conversions (C11 6.3.1.8), so `u == -1` is true
 * for `unsigned u = UINT_MAX`, whereas T_EXPECT_EQ(u, -1) fails -- UINT_MAX is
 * not -1.  An assertion may report a mismatch the language would have converted
 * away, but it must never accept a value the author did not write.  Where the
 * converted comparison is the intent, write T_EXPECT(u == -1).
 *
 * An integer and a floating operand are not folded into one category either:
 * `==` would round the integer to the floating type, and converting the other
 * way would truncate the floating value, so neither direction is exact.  Such a
 * pair goes to _if_ / _uf_ / _fi_ / _fu_, which hold it equal only when the
 * floating value is an integer the integer operand's type can hold, and is that
 * very integer -- T_EXPECT_EQ(n, 2.5) fails for `int n = 2`.
 *
 * A floating operand is compared as a value of its own type.  Where
 * FLT_EVAL_METHOD is 1 or 2, a floating expression -- a constant included -- may
 * carry more range and precision than its type (C11 5.2.4.2.2p9), and passing
 * it to a long double parameter keeps that excess: an inexact double constant
 * such as 1e308 would then keep its exact decimal value, which no stored double
 * equals.  So each operand travels with its kind (TESTING_EQ_KIND_), and
 * testing_eq_strip_ casts a floating one back to its own type, which removes
 * the excess (6.3.1.8p2) exactly as storing it in a variable of that type
 * would.  Two floating operands of different types then compare in the wider
 * one, as `==` compares them where FLT_EVAL_METHOD is 0.  A floating value is
 * reported with the digits its type needs to round-trip (FLT_DECIMAL_DIG and
 * kin), so a mismatch never prints two equal-looking numbers.
 *
 * T_EXPECT_EQ below dispatches on both operands with nested _Generic, keyed on
 * each operand's promoted type (see TESTING_PROMOTE_) so that a bit-field
 * operand reaches its own category instead of the pointer default.  Promotion
 * cannot change a verdict: it leaves every value exactly representable in the
 * selected variant's parameter type, and it takes the narrow types out of the
 * dispatch entirely.  The associations name only functions, never a cast of
 * `value_`/`expect_`.  A function reference type-checks regardless of which
 * branch _Generic ends up selecting, so, unlike a macro that casts its
 * argument inside every association (rejected: e.g. a pointer cannot cast to
 * long double, which would break the moment any branch mentions a
 * floating-point target), this never requires an operand to satisfy an
 * unrelated branch's type.  Both operands are converted once, by the ordinary
 * call to the selected function -- a generic selection leaves its controlling
 * expression unevaluated (C11 6.5.1.1) -- so each is evaluated exactly once no
 * matter the outcome, which matters when either is a side-effecting expression
 * such as a blocking read().
 */
/* The kind of a T_EXPECT_EQ operand, which tells testing_eq_strip_ the type a
 * floating one had before it was passed as long double. */
enum {
	TESTING_KIND_NONE_, /* an integer or a pointer */
	TESTING_KIND_FLT_,
	TESTING_KIND_DBL_,
	TESTING_KIND_LDBL_,
};

#define TESTING_EQ_KIND_(value_)                                               \
	_Generic(                                                              \
		TESTING_PROMOTE_(value_),                                      \
		float: TESTING_KIND_FLT_,                                      \
		double: TESTING_KIND_DBL_,                                     \
		long double: TESTING_KIND_LDBL_,                               \
		default: TESTING_KIND_NONE_)

/* Round `x` to the type `kind` names, dropping any excess precision. */
static inline long double testing_eq_strip_(long double x, int kind)
{
	switch (kind) {
	case TESTING_KIND_FLT_:
		return (float)x;
	case TESTING_KIND_DBL_:
		return (double)x;
	default:
		return x;
	}
}

/* The significant digits that print a value of type `kind` unambiguously. */
static inline int testing_eq_digits_(int kind)
{
	switch (kind) {
	case TESTING_KIND_FLT_:
		return FLT_DECIMAL_DIG;
	case TESTING_KIND_DBL_:
		return DBL_DECIMAL_DIG;
	default:
		return LDBL_DECIMAL_DIG;
	}
}

/* Whether the floating value `x` is exactly the integer `i`. */
static inline bool testing_eq_flt_int_(long double x, intmax_t i)
{
	/* 2^(N-1) for an N-bit intmax_t, a power of two every floating type
	 * holds exactly; [-lim, lim) is where the conversion below is defined. */
	const long double lim = -(long double)INTMAX_MIN;
	if (!(x >= -lim && x < lim)) {
		return false; /* out of range, or NaN */
	}
	const intmax_t t = (intmax_t)x;
	return t == i && (long double)t == x;
}

/* Whether the floating value `x` is exactly the integer `u`. */
static inline bool testing_eq_flt_uint_(long double x, uintmax_t u)
{
	/* 2^N for an N-bit uintmax_t, built from 2^(N-1) so that no step
	 * rounds; [0, lim) is where the conversion below is defined. */
	const long double lim = 2.0L * (long double)(UINTMAX_MAX / 2 + 1);
	if (!(x >= 0 && x < lim)) {
		return false; /* out of range, or NaN */
	}
	const uintmax_t t = (uintmax_t)x;
	return t == u && (long double)t == x;
}

static inline bool testing_eq_report_i_(
	FILE *out, const char *file, int line, intmax_t value, int vkind,
	intmax_t expect, int ekind)
{
	(void)vkind;
	(void)ekind;
	if (value == expect) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %jd, got %jd\n", file, line, expect,
		value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_u_(
	FILE *out, const char *file, int line, uintmax_t value, int vkind,
	uintmax_t expect, int ekind)
{
	(void)vkind;
	(void)ekind;
	if (value == expect) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %ju, got %ju\n", file, line, expect,
		value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_iu_(
	FILE *out, const char *file, int line, intmax_t value, int vkind,
	uintmax_t expect, int ekind)
{
	(void)vkind;
	(void)ekind;
	if (value >= 0 && (uintmax_t)value == expect) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %ju, got %jd\n", file, line, expect,
		value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_ui_(
	FILE *out, const char *file, int line, uintmax_t value, int vkind,
	intmax_t expect, int ekind)
{
	(void)vkind;
	(void)ekind;
	if (expect >= 0 && value == (uintmax_t)expect) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %jd, got %ju\n", file, line, expect,
		value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_f_(
	FILE *out, const char *file, int line, long double value, int vkind,
	long double expect, int ekind)
{
	const long double v = testing_eq_strip_(value, vkind);
	const long double e = testing_eq_strip_(expect, ekind);
	if (v == e) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %.*Lg, got %.*Lg\n", file, line,
		testing_eq_digits_(ekind), e, testing_eq_digits_(vkind), v);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_if_(
	FILE *out, const char *file, int line, intmax_t value, int vkind,
	long double expect, int ekind)
{
	(void)vkind;
	const long double e = testing_eq_strip_(expect, ekind);
	if (testing_eq_flt_int_(e, value)) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %.*Lg, got %jd\n", file, line,
		testing_eq_digits_(ekind), e, value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_uf_(
	FILE *out, const char *file, int line, uintmax_t value, int vkind,
	long double expect, int ekind)
{
	(void)vkind;
	const long double e = testing_eq_strip_(expect, ekind);
	if (testing_eq_flt_uint_(e, value)) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %.*Lg, got %ju\n", file, line,
		testing_eq_digits_(ekind), e, value);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_fi_(
	FILE *out, const char *file, int line, long double value, int vkind,
	intmax_t expect, int ekind)
{
	(void)ekind;
	const long double v = testing_eq_strip_(value, vkind);
	if (testing_eq_flt_int_(v, expect)) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %jd, got %.*Lg\n", file, line, expect,
		testing_eq_digits_(vkind), v);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_fu_(
	FILE *out, const char *file, int line, long double value, int vkind,
	uintmax_t expect, int ekind)
{
	(void)ekind;
	const long double v = testing_eq_strip_(value, vkind);
	if (testing_eq_flt_uint_(v, expect)) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %ju, got %.*Lg\n", file, line, expect,
		testing_eq_digits_(vkind), v);
	(void)fflush(out);
	return false;
}

static inline bool testing_eq_report_p_(
	FILE *out, const char *file, int line, const void *value, int vkind,
	const void *expect, int ekind)
{
	(void)vkind;
	(void)ekind;
	if (value == expect) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect %p, got %p\n", file, line, expect,
		value);
	(void)fflush(out);
	return false;
}

/*
 * The second dispatch level: having settled `value_`'s category, pick the
 * variant matching `expect_`'s.  A pointer `expect_` takes the default, so
 * pairing it with an arithmetic `value_` fails to compile, as it should.
 */
#define TESTING_EQ_FROM_I_(expect_)                                            \
	_Generic(                                                              \
		TESTING_PROMOTE_(expect_),                                     \
		unsigned int: testing_eq_report_iu_,                           \
		unsigned long: testing_eq_report_iu_,                          \
		unsigned long long: testing_eq_report_iu_,                     \
		float: testing_eq_report_if_,                                  \
		double: testing_eq_report_if_,                                 \
		long double: testing_eq_report_if_,                            \
		default: testing_eq_report_i_)
#define TESTING_EQ_FROM_U_(expect_)                                            \
	_Generic(                                                              \
		TESTING_PROMOTE_(expect_),                                     \
		signed int: testing_eq_report_ui_,                             \
		signed long: testing_eq_report_ui_,                            \
		signed long long: testing_eq_report_ui_,                       \
		float: testing_eq_report_uf_,                                  \
		double: testing_eq_report_uf_,                                 \
		long double: testing_eq_report_uf_,                            \
		default: testing_eq_report_u_)
#define TESTING_EQ_FROM_F_(expect_)                                            \
	_Generic(                                                              \
		TESTING_PROMOTE_(expect_),                                     \
		signed int: testing_eq_report_fi_,                             \
		signed long: testing_eq_report_fi_,                            \
		signed long long: testing_eq_report_fi_,                       \
		unsigned int: testing_eq_report_fu_,                           \
		unsigned long: testing_eq_report_fu_,                          \
		unsigned long long: testing_eq_report_fu_,                     \
		default: testing_eq_report_f_)

#define T_EXPECT_EQ(value_, expect_)                                           \
	do {                                                                   \
		if (!_Generic(                                                 \
			    TESTING_PROMOTE_(value_),                          \
			    signed int: TESTING_EQ_FROM_I_(expect_),           \
			    signed long: TESTING_EQ_FROM_I_(expect_),          \
			    signed long long: TESTING_EQ_FROM_I_(expect_),     \
			    unsigned int: TESTING_EQ_FROM_U_(expect_),         \
			    unsigned long: TESTING_EQ_FROM_U_(expect_),        \
			    unsigned long long: TESTING_EQ_FROM_U_(expect_),   \
			    float: TESTING_EQ_FROM_F_(expect_),                \
			    double: TESTING_EQ_FROM_F_(expect_),               \
			    long double: TESTING_EQ_FROM_F_(expect_),          \
			    default: testing_eq_report_p_)(                    \
			    (_t_)->out, __FILE__, __LINE__, (value_),          \
			    TESTING_EQ_KIND_(value_), (expect_),               \
			    TESTING_EQ_KIND_(expect_))) {                      \
			T_FAILNOW();                                           \
		}                                                              \
	} while (0)

/* Compare strings and report a mismatch to `out`; return true on equality. */
static inline bool testing_streq_report_(
	FILE *out, const char *file, int line, const char *value,
	const char *expect)
{
	if (strcmp(value, expect) == 0) {
		return true;
	}
	(void)fprintf(
		out, "    %s:%d expect \"%s\", got \"%s\"\n", file, line,
		expect, value);
	(void)fflush(out);
	return false;
}

static inline bool testing_memeq_report_(
	FILE *out, const char *file, int line, const void *value,
	const void *expect, size_t size)
{
	/* name the first difference: the byte count alone says nothing about
	 * how much of the buffer is wrong */
	const unsigned char *const v = value;
	const unsigned char *const e = expect;
	for (size_t i = 0; i < size; i++) {
		if (v[i] == e[i]) {
			continue;
		}
		(void)fprintf(
			out,
			"    %s:%d memory mismatch at offset %zu of %zu: expect 0x%02x, got 0x%02x\n",
			file, line, i, size, (unsigned)e[i], (unsigned)v[i]);
		(void)fflush(out);
		return false;
	}
	return true;
}

#define T_EXPECT_STREQ(value_, expect_)                                        \
	do {                                                                   \
		if (!testing_streq_report_(                                    \
			    (_t_)->out, __FILE__, __LINE__, (value_),          \
			    (expect_))) {                                      \
			T_FAILNOW();                                           \
		}                                                              \
	} while (0)

#define T_EXPECT_MEMEQ(value_, expect_, size_)                                 \
	do {                                                                   \
		if (!testing_memeq_report_(                                    \
			    (_t_)->out, __FILE__, __LINE__, (value_),          \
			    (expect_), (size_t)(size_))) {                     \
			T_FAILNOW();                                           \
		}                                                              \
	} while (0)

#endif /* UTILS_TESTING_H */
