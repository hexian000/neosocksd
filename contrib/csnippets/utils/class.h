/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_CLASS_H
#define UTILS_CLASS_H

/**
 * @defgroup class
 * @brief Tricky macros for class-like supports.
 * @{
 */

#define ASSERT_TYPE(type, value)                                               \
	((void)sizeof(struct {                                                 \
		_Static_assert(                                                \
			_Generic((value), type: 1, default: 0),                \
			"type assertion failed");                              \
		int _;                                                         \
	}))

#ifndef ASSERT_SUPER
#define ASSERT_SUPER(super, type, member)                                      \
	_Static_assert(                                                        \
		_Generic(&(((type *)0)->member), super *: 1, default: 0) &&    \
			(offsetof(type, member) == 0),                         \
		"ill-formed struct definition")
#endif

#ifndef DOWNCAST
#define DOWNCAST(from, to, member, ptr)                                        \
	(ASSERT_TYPE(from *, &(((to *)0)->member)),                            \
	 _Generic(                                                             \
		 (ptr),                                                        \
		 from *: (to *)(((unsigned char *)(ptr)) -                     \
				offsetof(to, member)),                         \
		 const from *: (const to *)(((unsigned char *)(ptr)) -         \
					    offsetof(to, member)),             \
		 volatile from *: (volatile to *)(((unsigned char *)(ptr)) -   \
						  offsetof(to, member)),       \
		 const volatile from *: (                                      \
			 const volatile to *)(((unsigned char *)(ptr)) -       \
					      offsetof(to, member))))
#endif

/** @} */

#endif /* UTILS_CLASS_H */
