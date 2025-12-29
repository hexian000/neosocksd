/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef PROTO_DOMAIN_H
#define PROTO_DOMAIN_H

#include <stddef.h>
#include <stdint.h>

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))

struct domain_name {
	uint8_t len;
	char name[FQDN_MAX_LENGTH];
};

#endif /* PROTO_DOMAIN_H */
