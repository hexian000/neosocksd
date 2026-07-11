/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_CLASS_H
#define META_CLASS_H

#include <assert.h>
#include <stddef.h>

/**
 * @defgroup class
 * @brief Tricky macros for class-like supports.
 * @{
 */

/**
 * @brief Compile-time check that `value` has type `type`.
 * @details Expression-safe: the check is wrapped in sizeof(struct {...})
 * so it can be used anywhere an expression is expected.
 */
#define ASSERT_TYPE(type, value)                                               \
	((void)sizeof(struct {                                                 \
		static_assert(                                                 \
			_Generic((value), type: 1, default: 0),                \
			"type assertion failed");                              \
		int _;                                                         \
	}))

/**
 * @brief Compile-time check that `member` is `type`'s first field and its
 * address has type `super *`.
 * @details A declaration, not an expression; use at file or block scope.
 */
#ifndef ASSERT_SUPER
#define ASSERT_SUPER(super, type, member)                                      \
	static_assert(                                                         \
		_Generic(&(((type *)0)->member), super *: 1, default: 0) &&    \
			(offsetof(type, member) == 0),                         \
		"ill-formed struct definition")
#endif

/**
 * @brief Cast a pointer to `member` back to a pointer to its owning `to`
 * struct (like container_of), preserving const/volatile qualification.
 */
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
#endif /* DOWNCAST */

/** @} */

#endif /* META_CLASS_H */
