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

uint32_t msg_cksum(const uint8_t *buf, size_t size)
{
	uint8_t hash1[32];
	uint8_t hash2[32];

	SHA256(buf, size, hash1);
	SHA256(hash1, sizeof(hash1), hash2);

	return (uint32_t)hash2[0]
	    | ((uint32_t)hash2[1] << 8)
	    | ((uint32_t)hash2[2] << 16)
	    | ((uint32_t)hash2[3] << 24);
}

size_t pack_header(uint8_t *buf, size_t buf_size, const char *cmd)
{
	if (buf_size < HDR_SIZE) {
		return 0;
	}

	buf[0] = 0xf9;
	buf[1] = 0xbe;
	buf[2] = 0xb4;
	buf[3] = 0xd9;

	strcpy((char *)buf + 4, cmd);
	size_t cmd_len = strlen(cmd);
	memset(buf + 4 + cmd_len, 0, 12 - cmd_len);

	// payload size and checksum fields are filled by
	// the concrete message pack function

	return HDR_SIZE;
}

size_t pack_version_msg(uint8_t *buf, size_t buf_size, const uint64_t *nonce)
{
	const struct in6_addr in6_loop = IN6ADDR_LOOPBACK_INIT;

	size_t len = 0;
	len += pack_header(buf + len, buf_size - len, "version");
	len += pack32(PROTOCOL_VERSION, buf + len, buf_size - len);
	len += pack64(0, buf + len, buf_size - len);
	len += pack64(time(NULL), buf + len, buf_size - len);
	len += pack64(NODE_NETWORK, buf + len, buf_size - len);
	len += pack_buf(&in6_loop, sizeof(in6_loop), buf + len, buf_size - len);
	len += pack16(htons(MAINNET_PORT), buf + len, buf_size - len);
	len += pack64(0, buf + len, buf_size - len);
	len += pack_buf(&in6_loop, sizeof(in6_loop), buf + len, buf_size - len);
	len += pack16(htons(MAINNET_PORT), buf + len, buf_size - len);
	len += pack64(*nonce, buf + len, buf_size - len);
	len += pack_cuint(NELEMS(USER_AGENT) - 1, buf + len, buf_size - len);
	len += pack_buf(USER_AGENT, NELEMS(USER_AGENT) - 1, buf + len, buf_size - len);
	len += pack32(0, buf + len, buf_size - len);
	len += pack8(0, buf + len, buf_size - len);

	pack32(len - HDR_SIZE, buf + HDR_PAYLOAD_SIZE_OFF, HDR_PAYLOAD_SIZE_SIZE);
	pack32(msg_cksum(buf + HDR_SIZE, len - HDR_SIZE), buf + HDR_CKSUM_OFF, HDR_CKSUM_SIZE);

	return len;
}

size_t pack_payloadless_msg(uint8_t *buf, size_t buf_size, const char *cmd)
{
	size_t len = pack_header(buf, buf_size, cmd);
	pack32(0, buf + HDR_PAYLOAD_SIZE_OFF, HDR_PAYLOAD_SIZE_SIZE);
	pack32(PAYLOADLESS_MSG_CKSUM, buf + HDR_CKSUM_OFF, HDR_CKSUM_SIZE);
	return len;
}

size_t pack_verack_msg(uint8_t *buf, size_t buf_size)
{
	return pack_payloadless_msg(buf, buf_size, "verack");
}

size_t pack_getaddr_msg(uint8_t *buf, size_t buf_size)
{
	return pack_payloadless_msg(buf, buf_size, "getaddr");
}

bool parse_hdr(uint8_t *buf, size_t buf_size, struct hdr *hdr)
{
	if (buf_size < HDR_SIZE) {
		return false;
	}

	size_t off = 0;
	off += unpack32(&hdr->magic, buf, buf_size);
	memcpy(hdr->cmd, buf + off, HDR_CMD_SIZE);
	off += HDR_CMD_SIZE;
	off += unpack32(&hdr->payload_size, buf + off, buf_size - off);
	off += unpack32(&hdr->cksum, buf + off, buf_size - off);

	if (hdr->magic != (uint32_t)0xd9b4bef9) {
		printf("parse_hdr: wrong magic number\n");
		return false;
	}
	if (hdr->payload_size > (buf_size - HDR_SIZE)) {
		printf("parse_hdr: payload size greater than buffer size\n");
		return false;
	}
	uint32_t cksum;
	if (hdr->payload_size == 0) {
		cksum = PAYLOADLESS_MSG_CKSUM;
	} else {
		cksum = msg_cksum(buf + HDR_SIZE, hdr->payload_size);
	}
	if (hdr->cksum != cksum) {
		printf("parse_hdr: payload checksum is invalid, %08x but should be %08x\n", hdr->cksum, cksum);
		return false;
	}
	return true;
}

bool parse_version_msg(uint8_t *buf, size_t buf_size, struct version *ver)
{
	struct hdr hdr;
	if (!parse_hdr(buf, buf_size, &hdr)) {
		return false;
	}

	uint8_t *msg = buf + HDR_SIZE;
	size_t msg_len = hdr.payload_size;

	if (msg_len < VERSION_MIN_PAYLOAD_SIZE) {
		return false;
	}

	uint64_t ua_len = 0;
	size_t ua_off;
	if (unpack32(&ver->protocol, msg, msg_len)
	    && unpack64(&ver->services, msg + VERSION_SERVICES_OFF, msg_len - VERSION_SERVICES_OFF)
	    && VERSION_UA_LEN_OFF < msg_len
	    && (ua_off = unpack_cuint(&ua_len, msg + VERSION_UA_LEN_OFF, msg_len - VERSION_UA_LEN_OFF))
	    && (ua_off += VERSION_UA_LEN_OFF)
	    && (ua_off + ua_len) < msg_len
	    && unpack32(&ver->start_height, msg + ua_off + ua_len, msg_len - (ua_off + ua_len))) {
		if (ua_len > sizeof(ver->user_agent)-1) {
			ua_len = sizeof(ver->user_agent)-1;
		}
		memcpy(ver->user_agent, msg + ua_off, ua_len);
		ver->user_agent[ua_len] = '\0';
		return true;
	} else {
		return false;
	}
}
