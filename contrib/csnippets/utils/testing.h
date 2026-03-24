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
	const char *current;
	volatile bool case_failed : 1;
	volatile bool case_skipped : 1;
	jmp_buf case_jmp;
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
		(void)fprintf((ctx_).out, ">>> RUN   %s\n", #name_);           \
		(void)fflush((ctx_).out);                                      \
		if (setjmp((ctx_).case_jmp) == 0) {                            \
			_testcase_##name_##_(&(ctx_));                         \
		}                                                              \
		if ((ctx_).case_failed) {                                      \
			(ctx_).failed++;                                       \
			(void)fprintf((ctx_).out, "<<< FAIL  %s\n", #name_);   \
		} else if ((ctx_).case_skipped) {                              \
			(ctx_).skipped++;                                      \
			(void)fprintf((ctx_).out, "<<< SKIP  %s\n", #name_);   \
		} else {                                                       \
			(ctx_).passed++;                                       \
			(void)fprintf((ctx_).out, "<<< PASS  %s\n", #name_);   \
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

#endif /* UTILS_TESTING_H */
