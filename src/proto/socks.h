/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef PROTO_SOCKS_H
#define PROTO_SOCKS_H

#include "domain.h"

#include <stdint.h>

enum socks_version {
	SOCKS4 = UINT8_C(0x04),
	SOCKS5 = UINT8_C(0x05),
};

struct socks4_hdr {
	uint8_t version;
	uint8_t command;
	uint16_t port;
	uint32_t address;
};

enum socks4_command {
	SOCKS4CMD_CONNECT = 1,
};

enum socks4_response {
	/* request granted */
	SOCKS4RSP_GRANTED = 90,
	/* request rejected or failed */
	SOCKS4RSP_REJECTED = 91,
};

enum socks5_address_type {
	SOCKS5ADDR_IPV4 = UINT8_C(0x01),
	SOCKS5ADDR_DOMAIN = UINT8_C(0x03),
	SOCKS5ADDR_IPV6 = UINT8_C(0x04),
};

enum socks5_authenticate_method {
	SOCKS5AUTH_NOAUTH = UINT8_C(0x00),
	SOCKS5AUTH_NOACCEPTABLE = UINT8_C(0xFF),
};

enum socks5_command {
	SOCKS5CMD_CONNECT = UINT8_C(0x01),
	SOCKS5CMD_BIND = UINT8_C(0x02),
	SOCKS5CMD_UDPASSOCIATE = UINT8_C(0x03),
};

enum socks5_response {
	/* succeeded */
	SOCKS5RSP_SUCCEEDED = UINT8_C(0x00),
	/* general SOCKS server failure */
	SOCKS5RSP_FAIL = UINT8_C(0x01),
	/* connection not allowed by ruleset */
	SOCKS5RSP_NOALLOWED = UINT8_C(0x02),
	/* Network unreachable */
	SOCKS5RSP_NETUNREACH = UINT8_C(0x03),
	/* Host unreachable */
	SOCKS5RSP_HOSTUNREACH = UINT8_C(0x04),
	/* Connection refused */
	SOCKS5RSP_CONNREFUSED = UINT8_C(0x05),
	/* TTL expired */
	SOCKS5RSP_TTLEXPIRED = UINT8_C(0x06),
	/* Command not supported */
	SOCKS5RSP_CMDNOSUPPORT = UINT8_C(0x07),
	/* Address type not supported */
	SOCKS5RSP_ATYPNOSUPPORT = UINT8_C(0x08),

	SOCKS5RSP_MAX = UINT8_C(0x09),
};

struct socks5_auth_req {
	uint8_t version;
	uint8_t nmethods;
	uint8_t methods[];
};

struct socks5_auth_rsp {
	uint8_t version;
	uint8_t method;
};

struct socks5_hdr {
	uint8_t version;
	uint8_t command;
	uint8_t reserved;
	uint8_t addrtype;
};

#define SOCKS_MAX_LENGTH                                                       \
	(MAX(sizeof(struct socks4_hdr) + (255 + 1) /* ident */ +               \
		     (FQDN_MAX_LENGTH + 1),                                    \
	     sizeof(struct socks5_auth_req) + 255 /* methods */ +              \
		     sizeof(struct socks5_hdr) +                               \
		     MAX(MAX(sizeof(struct in_addr) + sizeof(in_port_t),       \
			     sizeof(struct in6_addr) + sizeof(in_port_t)),     \
			 1 + FQDN_MAX_LENGTH + sizeof(in_port_t))))

#endif /* PROTO_SOCKS_H */
