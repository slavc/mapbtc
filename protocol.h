/*
 * Copyright (c) 2018 Sviatoslav Chagaev <sviatoslav.chagaev@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef MAPBTC_PROTOCOL_H
#define MAPBTC_PROTOCOL_H

#include <stdlib.h>
#include <stdint.h>

#define NELEMS(a) (sizeof(a)/sizeof(*(a)))

#define USER_AGENT "/mapbtc:0.0.1/"

#define MAINNET_PORT 8333
#define NODE_NETWORK 1
#define MAX_MSG_SIZE (32*1024*1024)
#define PROTOCOL_VERSION 70015

struct hdr {
	uint32_t magic;
	char cmd[12];
	uint32_t payload_size;
	uint32_t cksum;
};
#define HDR_MAGIC 0xd9b4bef9
#define HDR_MAGIC_SIZE 4
#define HDR_CMD_SIZE 12
#define HDR_PAYLOAD_SIZE_SIZE 4
#define HDR_CKSUM_SIZE 4
#define HDR_MAGIC_OFF 0
#define HDR_CMD_OFF 4
#define HDR_PAYLOAD_SIZE_OFF (4+12)
#define HDR_CKSUM_OFF (4+12+4)
#define HDR_SIZE (HDR_MAGIC_SIZE + HDR_CMD_SIZE + HDR_PAYLOAD_SIZE_SIZE + HDR_CKSUM_SIZE)
bool peek_hdr(uint8_t *buf, size_t buf_size, struct hdr *hdr);
bool unpack_hdr(uint8_t *buf, size_t buf_size, struct hdr *hdr);
inline bool is_version_msg(const struct hdr *hdr)
{
	return memcmp(hdr->cmd, "version\0\0\0\0\0", HDR_CMD_SIZE) == 0;
}
inline bool is_addr_msg(const struct hdr *hdr)
{
	return memcmp(hdr->cmd, "addr\0\0\0\0\0\0\0\0", HDR_CMD_SIZE) == 0;
}

#define ADDR_IP_SIZE 16
#define ADDR_IP_OFF (4+8)
#define ADDR_REC_SIZE (4+8+16+2) // size of one record in addr message

struct version {
	uint32_t protocol; // version of protocol
	uint64_t services;
	char user_agent[128];
	uint32_t start_height;
};
bool unpack_version_msg(uint8_t *buf, size_t size, struct version *ver);

struct addr {
	uint64_t num;
	void *rec_ptr;
};
struct addr_record {
	uint32_t t;
	uint64_t services;
	struct in6_addr ip;
	uint16_t port;
};
#define ADDR_RECORD_SIZE (4+8+16+2)
bool unpack_addr_msg(uint8_t *buf, size_t size, struct addr *addr);
bool unpack_addr_record(struct addr *, struct addr_record *);

uint32_t msg_cksum(const void *buf, size_t size);

size_t pack_header(uint8_t *buf, size_t buf_size, const char *cmd, const void *payload, size_t payload_size);
size_t pack_version_msg(uint8_t *buf, size_t buf_size, const uint64_t nonce);
size_t pack_payloadless_msg(uint8_t *buf, size_t buf_size, const char *cmd);
size_t pack_verack_msg(uint8_t *buf, size_t buf_size);
size_t pack_getaddr_msg(uint8_t *buf, size_t buf_size);

#endif
