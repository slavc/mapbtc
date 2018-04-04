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

#include <netinet/in.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "sha256.h"
#include "pack.h"
#include "protocol.h"

#define PAYLOADLESS_MSG_CKSUM 0xe2e0f65d

void SHA256(const void *data, size_t len, uint8_t *hash)
{
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, hash);
}

uint32_t msg_cksum(const void *buf, size_t size)
{
	if (size == 0) {
		return PAYLOADLESS_MSG_CKSUM;
	}

	uint8_t hash1[32];
	uint8_t hash2[32];

	SHA256(buf, size, hash1);
	SHA256(hash1, sizeof(hash1), hash2);

	return (uint32_t)hash2[0]
	    | ((uint32_t)hash2[1] << 8)
	    | ((uint32_t)hash2[2] << 16)
	    | ((uint32_t)hash2[3] << 24);
}

size_t pack_header(uint8_t *buf, size_t size, const char *cmd, const void *payload, size_t payload_size)
{
	size_t len;
	size_t off;
	uint32_t cksum;

	len = off = 0;

	PACKLE32(HDR_MAGIC);
	strncpy((char *)buf + 4, cmd, 12);
	size_t cmd_len = strlen(cmd);
	if (cmd_len < 12) {
		memset(buf + 4 + cmd_len, 0, 12 - cmd_len);
	}
	len += 12;
	off += 12;
	PACKLE32(payload_size);
	cksum = msg_cksum(payload, payload_size);
	PACKLE32(cksum);

	return HDR_SIZE;
}

size_t pack_version_msg(uint8_t *buf, size_t size, const uint64_t nonce)
{
	const struct in6_addr in6_loop = IN6ADDR_LOOPBACK_INIT;
	const size_t my_user_agent_len = NELEMS(USER_AGENT) - 1;
	const time_t now = time(NULL);

	size_t len;
	size_t off;

	len = off = HDR_SIZE;

	PACKLE32(PROTOCOL_VERSION);
	PACKLE64(0);
	PACKLE64(now);
	PACKLE64(NODE_NETWORK);
	PACKN(&in6_loop, sizeof(in6_loop));
	PACKBE16(MAINNET_PORT);
	PACKLE64(0);
	PACKN(&in6_loop, sizeof(in6_loop));
	PACKBE16(MAINNET_PORT);
	PACKLE64(nonce);
	PACKCINT(my_user_agent_len);
	PACKN(USER_AGENT, my_user_agent_len);
	PACKLE32(0);
	PACK8(0);
	if (off == len) {
		(void)pack_header(buf, size, "version",
		    buf + HDR_SIZE, len - HDR_SIZE);
	}

	return len;
}

size_t pack_payloadless_msg(uint8_t *buf, size_t buf_size, const char *cmd)
{
	return pack_header(buf, buf_size, cmd, NULL, 0);
}

size_t pack_verack_msg(uint8_t *buf, size_t buf_size)
{
	return pack_payloadless_msg(buf, buf_size, "verack");
}

size_t pack_getaddr_msg(uint8_t *buf, size_t buf_size)
{
	return pack_payloadless_msg(buf, buf_size, "getaddr");
}

// FIXME Use proper logging functions throughout the code.

bool peek_hdr(uint8_t *buf, size_t size, struct hdr *hdr)
{
	UNPACKLE32(hdr->magic);
	UNPACKN(&hdr->cmd, sizeof(hdr->cmd));
	UNPACKLE32(hdr->payload_size);
	UNPACKLE32(hdr->cksum);

	if (hdr->magic != (uint32_t)0xd9b4bef9) {
		printf("unpack_hdr: wrong magic number\n");
		return false;
	}
	return true;
}

bool unpack_hdr(uint8_t *buf, size_t size, struct hdr *hdr)
{
	UNPACKLE32(hdr->magic);
	UNPACKN(&hdr->cmd, sizeof(hdr->cmd));
	UNPACKLE32(hdr->payload_size);
	UNPACKLE32(hdr->cksum);

	if (hdr->magic != (uint32_t)HDR_MAGIC) {
		printf("unpack_hdr: wrong magic number\n");
		return false;
	}

	if (hdr->payload_size != size) {
		printf("unpack_hdr: wrong payload size\n");
		return false;
	}

	uint32_t cksum;
	if (hdr->payload_size == 0) {
		cksum = PAYLOADLESS_MSG_CKSUM;
	} else {
		cksum = msg_cksum(buf, hdr->payload_size);
	}
	if (hdr->cksum != cksum) {
		printf("unpack_hdr: payload checksum is invalid, %08x but should be %08x\n", hdr->cksum, cksum);
		return false;
	}

	return true;
}

bool unpack_version_msg(uint8_t *buf, size_t size, struct version *ver)
{
	uint64_t ua_len;

	SKIP(HDR_SIZE);

	UNPACKLE32(ver->protocol);
	UNPACKLE64(ver->services);
	SKIP(8); // timestamp
	SKIP(8); // msg recevier's services
	SKIP(16); // msg receiver's IPv6 addr
	SKIP(2); // msg receiver's port
	SKIP(8); // msg sender's services
	SKIP(16); // msg sender's IPv6 addr
	SKIP(2); // msg sender's port
	SKIP(8); // nonce
	UNPACKCINT(ua_len); // length of user agent string
		uint64_t len = ua_len;
		if (len >= sizeof(ver->user_agent)) {
			len = sizeof(ver->user_agent) - 1;
		}
	UNPACKN(&ver->user_agent, len);
		ver->user_agent[len] = '\0';
		SKIP(ua_len - len);
	UNPACKLE32(ver->start_height);
	SKIP(sizeof(uint8_t)); // relay flag

	if (size != 0) {
		return false;
	}

	return true;
}

bool unpack_addr_msg(uint8_t *buf, size_t size, struct addr *a)
{
	SKIP(HDR_SIZE);
	UNPACKCINT(a->num);
	if (size % ADDR_RECORD_SIZE != 0) {
		return false;
	}
	if (a->num != size / ADDR_RECORD_SIZE) {
		return false;
	}
	a->rec_ptr = buf;
	return true;
}

bool unpack_addr_record(struct addr *a, struct addr_record *r)
{
	if (a->num == 0) {
		return false;
	}
	uint8_t *buf = a->rec_ptr;
	size_t size = a->num * ADDR_RECORD_SIZE;
	UNPACKLE32(r->t);
	UNPACKLE64(r->services);
	UNPACKN(&r->ip, 16);
	UNPACKLE16(r->port);
	a->num--;
	a->rec_ptr = buf;
	return true;
}

