/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @defgroup object
 * @brief Tricky macros for class-like supports.
 * @{
 */

#ifndef ASSERT_SUPER
#define ASSERT_SUPER(super, type, member)                                      \
	_Static_assert(                                                        \
		_Generic(&(((type *)0)->member), super * : 1, default : 0) &&  \
			(offsetof(type, member) == 0),                         \
		"ill-formed struct definition")
#endif

#ifndef DOWNCAST
#define DOWNCAST(from, to, member, ptr)                                        \
	((void)sizeof(struct{                                                  \
		_Static_assert(_Generic(&(((to *)0)->member),                  \
			from * : 1, default : 0), "member type mismatch");     \
		int _; }),                                                     \
	_Generic((ptr),                                                        \
	from * : (to *)                                                        \
		(((unsigned char *)(ptr)) - offsetof(to, member)),             \
	const from * : (const to *)                                            \
		(((unsigned char *)(ptr)) - offsetof(to, member)),             \
	volatile from * : (volatile to *)                                      \
		(((unsigned char *)(ptr)) - offsetof(to, member)),             \
	const volatile from * : (const volatile to *)                          \
		(((unsigned char *)(ptr)) - offsetof(to, member))))
#endif

/** @} */
