/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef INTLOG2_H
#define INTLOG2_H

#include <assert.h>

/* If C23 is available, prefer stdc */
#if __STDC_VERSION_STDBIT_H__ >= 202311L
#include <stdbit.h>

static inline int log2u(unsigned int x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - stdc_first_trailing_zeroui(x);
}
static inline int log2ul(unsigned long x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - stdc_first_trailing_zeroul(x);
}
static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - stdc_first_trailing_zeroull(x);
}

#define intlog2(x)                                                             \
	_Generic((x), unsigned int                                             \
		 : log2u, unsigned long                                        \
		 : log2ul, unsigned long long                                  \
		 : log2ull)(x)

#define countr_zero(x) stdc_first_trailing_zero(x)

#else
/* For C17 or earlier */

#include <stdint.h>

extern const int debruijn_bsr32[32];
static inline int log2u32(uint32_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	return debruijn_bsr32[(x * UINT32_C(0x07C4ACDD)) >> 27u];
}

extern const int debruijn_bsr64[64];
static inline int log2u64(uint64_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	x |= x >> 32u;
	return debruijn_bsr64[(x * UINT64_C(0x03F79D71B4CB0A89)) >> 58u];
}

/**
 * @brief returns the floored base-2 logarithm of x
 * @param x if 0, the behavior is undefined
 */
#define stdintlog2(x)                                                          \
	_Generic((x), uint8_t                                                  \
		 : log2u32, uint16_t                                           \
		 : log2u32, uint32_t                                           \
		 : log2u32, uint64_t                                           \
		 : log2u64)(x)

extern const int debruijn_bsf64[64];
static inline int countr_zerou64(uint64_t x)
{
	assert(x > 0);
	return debruijn_bsf64[((x & -x) * UINT64_C(0x0257EDD4D0F22CE3)) >> 58u];
}

/**
 * @brief bit scan forward
 * @param x if 0, the behavior is undefined
 */
#define stdcountr_zero(x)                                                      \
	_Generic((x), uint8_t                                                  \
		 : countr_zerou64, uint16_t                                    \
		 : countr_zerou64, uint32_t                                    \
		 : countr_zerou64, uint64_t                                    \
		 : countr_zerou64)(x)

/* prefer builtins when available */
#if defined(__has_builtin)
#if __has_builtin(__builtin_clz)
static inline int log2u(unsigned int x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clz(x);
}
#else
static inline int log2u(unsigned int x)
{
	return stdintlog2(x);
}
#endif /* __has_builtin(__builtin_clz) */

#if __has_builtin(__builtin_clzl)
static inline int log2ul(unsigned long x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clzl(x);
}
#else
static inline int log2ul(unsigned long x)
{
	return stdintlog2(x);
}
#endif /* __has_builtin(__builtin_clzl) */

#if __has_builtin(__builtin_clzll)
static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clzll(x);
}
#else
static inline int log2ull(unsigned long long x)
{
	return stdintlog2(x);
}
#endif /* __has_builtin(__builtin_clzll) */

/**
 * @brief Returns the floored base-2 logarithm of x
 * @param x if 0, the behavior is undefined
 */
#define intlog2(x)                                                             \
	_Generic((x), unsigned int                                             \
		 : log2u, unsigned long                                        \
		 : log2ul, unsigned long long                                  \
		 : log2ull)(x)

#else
#define intlog2(x) stdintlog2(x)
#endif /* defined(__has_builtin) */

/**
 * @brief Returns the number of consecutive 0 bits in the value of x,</br>
 * starting from the least significant bit ("right"). 
 * @param x if 0, the behavior is undefined
 */
#if defined(__has_builtin)
#if __has_builtin(__builtin_ctz)
static inline int countr_zerou(unsigned int x)
{
	assert(x > 0);
	return __builtin_ctz(x);
}
#else
static inline int countr_zerou(unsigned int x)
{
	return stdcountr_zero(x);
}
#endif /* __has_builtin(__builtin_ctz) */
#if __has_builtin(__builtin_ctzl)
static inline int countr_zeroul(unsigned long x)
{
	assert(x > 0);
	return __builtin_ctzl(x);
}
#else
static inline int countr_zeroul(unsigned long x)
{
	return stdcountr_zero(x);
}
#endif /* __has_builtin(__builtin_ctzl) */
#if __has_builtin(__builtin_ctzll)
static inline int countr_zeroull(unsigned long long x)
{
	assert(x > 0);
	return __builtin_ctzll(x);
}
#else
static inline int countr_zeroull(unsigned long long x)
{
	return stdcountr_zero(x);
}
#endif /* __has_builtin(__builtin_ctzll) */

#define countr_zero(x)                                                         \
	_Generic((x), unsigned int                                             \
		 : countr_zerou, unsigned long                                 \
		 : countr_zeroul, unsigned long long                           \
		 : countr_zeroull)(x)

#else
#define countr_zero(x) stdcountr_zero(x)
#endif /* defined(__has_builtin) */

#endif /* __STDC_VERSION_STDBIT_H__ >= 202311L */

#endif /* INTLOG2_H */
