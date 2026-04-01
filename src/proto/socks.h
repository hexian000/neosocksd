/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef PROTO_SOCKS_H
#define PROTO_SOCKS_H

#include "domain.h"

#include "utils/serialize.h"

#include <netinet/in.h>

#include <stdint.h>

enum socks_version {
	SOCKS4 = UINT8_C(0x04),
	SOCKS5 = UINT8_C(0x05),
};

/* SOCKS 4 Protocol (Ying-Da Lee, 1996)
 *
 * Request:
 *  +----+----+----+----+----+----+----+----+----+....+----+
 *  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
 *  +----+----+----+----+----+----+----+----+----+....+----+
 *     1    1       2              4           variable       1
 *
 * Reply:
 *  +----+----+----+----+----+----+----+----+
 *  | VN | CD | DSTPORT |      DSTIP        |
 *  +----+----+----+----+----+----+----+----+
 *     1    1       2              4
 */
struct socks4_hdr {
	uint_least8_t version;
	uint_least8_t command;
	uint_least16_t port; /* host byte order */
	uint_least32_t address; /* host byte order */
};

enum socks4_command {
	SOCKS4CMD_CONNECT = 1, /* 0x01 */
};

enum socks4_response {
	/* request granted */
	SOCKS4RSP_GRANTED = 90, /* 0x5A */
	/* request rejected or failed */
	SOCKS4RSP_REJECTED = 91, /* 0x5B */
};

enum socks5_address_type {
	SOCKS5ADDR_IPV4 = UINT8_C(0x01),
	SOCKS5ADDR_DOMAIN = UINT8_C(0x03),
	SOCKS5ADDR_IPV6 = UINT8_C(0x04),
};

enum socks5_authenticate_method {
	SOCKS5AUTH_NOAUTH = UINT8_C(0x00),
	SOCKS5AUTH_USERPASS = UINT8_C(0x02),
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
};

/* RFC 1928 §3 — Method selection:
 *
 *  +----+----------+----------+
 *  |VER | NMETHODS | METHODS  |
 *  +----+----------+----------+
 *  | 1  |    1     | 1 to 255 |
 *  +----+----------+----------+
 *
 *  +----+--------+
 *  |VER | METHOD |
 *  +----+--------+
 *  | 1  |   1    |
 *  +----+--------+
 */
struct socks5_auth_req {
	uint_least8_t version;
	uint_least8_t nmethods;
	uint_least8_t methods[];
};

struct socks5_auth_rsp {
	uint_least8_t version;
	uint_least8_t method;
};

/* RFC 1928 §4 — Request / Reply:
 *
 *  +----+-----+-------+------+----------+----------+
 *  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *  +----+-----+-------+------+----------+----------+
 *  | 1  |  1  | X'00' |  1   | Variable |    2     |
 *  +----+-----+-------+------+----------+----------+
 */
struct socks5_hdr {
	uint_least8_t version;
	uint_least8_t command;
	uint_least8_t reserved;
	uint_least8_t addrtype;
};

/* wire sizes of fixed-length header regions */
#define SOCKS4_HDR_LEN 8 /* version(1)+command(1)+port(2)+address(4) */
#define SOCKS5_AUTH_REQ_FIXED_LEN 2 /* version(1)+nmethods(1) */
#define SOCKS5_AUTH_RSP_LEN 2 /* version(1)+method(1) */
#define SOCKS5_HDR_LEN 4 /* version(1)+command(1)+reserved(1)+addrtype(1) */
#define SOCKS5_UDP_HDR_LEN 4 /* reserved(2)+frag(1)+addrtype(1) */
#define SOCKS5_RSP_MAXLEN                                                      \
	(SOCKS5_HDR_LEN + sizeof(struct in6_addr) + sizeof(in_port_t))

#define SOCKS4A_REQ_MAXLEN                                                     \
	(SOCKS4_HDR_LEN + 512 + /* ident */                                    \
	 (FQDN_MAX_LENGTH + 1))

#define SOCKS4_RSP_MINLEN SOCKS4_HDR_LEN

#define SOCKS5_REQ_MAXLEN                                                      \
	(SOCKS5_AUTH_REQ_FIXED_LEN + 255 + /* methods */                       \
	 1 + 256 + 256 + /* userpass auth */                                   \
	 SOCKS5_HDR_LEN +                                                      \
	 MAX(MAX(sizeof(struct in_addr) + sizeof(in_port_t),                   \
		 sizeof(struct in6_addr) + sizeof(in_port_t)),                 \
	     1 + FQDN_MAX_LENGTH + sizeof(in_port_t)))

#define SOCKS5_RSP_MINLEN                                                      \
	(SOCKS5_HDR_LEN + sizeof(struct in_addr) + sizeof(in_port_t))

#define SOCKS_REQ_MAXLEN (MAX(SOCKS4A_REQ_MAXLEN, SOCKS5_REQ_MAXLEN))

/* RFC 1928 §7 — UDP request/response header:
 *
 *  +----+------+------+----------+----------+----------+
 *  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *  +----+------+------+----------+----------+----------+
 *  | 2  |  1   |  1   | Variable |    2     | Variable |
 *  +----+------+------+----------+----------+----------+
 *
 * frag field encoding: bits[6:0] = fragment sequence number (1-based),
 * bit[7] = 1 on the last fragment of a sequence, 0 otherwise.
 * frag == 0x00 means the datagram is not fragmented. */
struct socks5_udp_hdr {
	uint_least8_t reserved[2];
	uint_least8_t frag;
	uint_least8_t addrtype;
};

#define SOCKS5_UDP_FRAG_LAST UINT8_C(0x80)

#define SOCKS5_UDP_HDR_IPV4LEN                                                 \
	(SOCKS5_UDP_HDR_LEN + sizeof(struct in_addr) + sizeof(in_port_t))
#define SOCKS5_UDP_HDR_IPV6LEN                                                 \
	(SOCKS5_UDP_HDR_LEN + sizeof(struct in6_addr) + sizeof(in_port_t))
#define SOCKS5_UDP_HDR_MAXLEN SOCKS5_UDP_HDR_IPV6LEN

static inline void
socks4hdr_read(struct socks4_hdr *restrict dst, const void *restrict src)
{
	const unsigned char *b = src;
	dst->version = b[0];
	dst->command = b[1];
	dst->port = read_uint16(b + 2);
	dst->address = read_uint32(b + 4);
}

static inline void
socks4hdr_write(void *restrict dst, const struct socks4_hdr *restrict src)
{
	unsigned char *b = dst;
	b[0] = (unsigned char)src->version;
	b[1] = (unsigned char)src->command;
	write_uint16(b + 2, src->port);
	write_uint32(b + 4, src->address);
}

static inline void socks5authreq_read(
	struct socks5_auth_req *restrict dst, const void *restrict src)
{
	const unsigned char *b = src;
	dst->version = b[0];
	dst->nmethods = b[1];
}

static inline void socks5authrsp_read(
	struct socks5_auth_rsp *restrict dst, const void *restrict src)
{
	const unsigned char *b = src;
	dst->version = b[0];
	dst->method = b[1];
}

static inline void socks5authrsp_write(
	void *restrict dst, const struct socks5_auth_rsp *restrict src)
{
	unsigned char *b = dst;
	b[0] = (unsigned char)src->version;
	b[1] = (unsigned char)src->method;
}

static inline void
socks5hdr_read(struct socks5_hdr *restrict dst, const void *restrict src)
{
	const unsigned char *b = src;
	dst->version = b[0];
	dst->command = b[1];
	dst->reserved = b[2];
	dst->addrtype = b[3];
}

static inline void
socks5hdr_write(void *restrict dst, const struct socks5_hdr *restrict src)
{
	unsigned char *b = dst;
	b[0] = (unsigned char)src->version;
	b[1] = (unsigned char)src->command;
	b[2] = (unsigned char)src->reserved;
	b[3] = (unsigned char)src->addrtype;
}

static inline void
socks5udphdr_read(struct socks5_udp_hdr *restrict dst, const void *restrict src)
{
	const unsigned char *b = src;
	dst->reserved[0] = b[0];
	dst->reserved[1] = b[1];
	dst->frag = b[2];
	dst->addrtype = b[3];
}

static inline void socks5udphdr_write(
	void *restrict dst, const struct socks5_udp_hdr *restrict src)
{
	unsigned char *b = dst;
	b[0] = (unsigned char)src->reserved[0];
	b[1] = (unsigned char)src->reserved[1];
	b[2] = (unsigned char)src->frag;
	b[3] = (unsigned char)src->addrtype;
}

#endif /* PROTO_SOCKS_H */
