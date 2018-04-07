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

#ifndef MAPBTC_PACK_H
#define MAPBTC_PACK_H

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define SKIP(n)									\
	if (size < n) {								\
		return false;							\
	}									\
	buf += n;								\
	size -= n;

#define PACK8(val)								\
	if (size >= len + 1) {							\
		buf[off++] = (uint8_t)val;					\
	}									\
	len += 1;

#define PACKBE16(val)								\
	if (size >= len + sizeof(uint16_t)) {					\
		buf[off++] = (uint8_t)((uint16_t)val >> 8);			\
		buf[off++] = (uint8_t)((uint16_t)val);				\
	}									\
	len += sizeof(uint16_t);

#define PACKLE16(val)								\
	if (size >= len + sizeof(uint16_t)) {					\
		buf[off++] = (uint8_t)((uint16_t)val);				\
		buf[off++] = (uint8_t)((uint16_t)val >> 8);			\
	}									\
	len += sizeof(uint16_t);

#define PACKLE32(val)								\
	if (size >= len + sizeof(uint32_t)) {					\
		buf[off++] = (uint8_t)val;					\
		buf[off++] = (uint8_t)((uint32_t)val >> 8);			\
		buf[off++] = (uint8_t)((uint32_t)val >> 16);			\
		buf[off++] = (uint8_t)((uint32_t)val >> 24);			\
	}									\
	len += sizeof(uint32_t);

#define PACKLE64(val)								\
	if (size >= len + sizeof(uint64_t)) {					\
		buf[off++] = (uint8_t)(val);					\
		buf[off++] = (uint8_t)((uint64_t)val >> 8);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 16);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 24);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 32);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 40);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 48);			\
		buf[off++] = (uint8_t)((uint64_t)val >> 56);			\
	}									\
	len += sizeof(uint64_t);

#define PACKCINT(val)								\
	if (val <= 252u) {							\
		if (size >= len + 1) {						\
			buf[off++] = (uint8_t)val;				\
		}								\
		len += 1;							\
	} else if (val <= 0xffffu) {						\
		if (size >= len + 3) {						\
			buf[off++] = (uint8_t)0xfd;				\
			buf[off++] = (uint8_t)val;				\
			buf[off++] = (uint8_t)((uint32_t)val >> 8);		\
		}								\
		len += 3;							\
	} else if (val <= 0xfffffffful) {					\
		if (size >= len + 5) {						\
			buf[off++] = 0xfe;					\
			buf[off++] = (uint8_t)val;				\
			buf[off++] = (uint8_t)((uint32_t)val >> 8);		\
			buf[off++] = (uint8_t)((uint32_t)val >> 16);		\
			buf[off++] = (uint8_t)((uint32_t)val >> 24);		\
		}								\
		len += 5;							\
	} else if (val <= 0xffffffffffffffffull) {				\
		if (size >= len + 9) {						\
			buf[off++] = 0xff;					\
			buf[off++] = (uint8_t)(val);				\
			buf[off++] = (uint8_t)((uint64_t)val >> 8);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 16);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 24);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 32);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 49);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 48);		\
			buf[off++] = (uint8_t)((uint64_t)val >> 56);		\
		}								\
		len += 9;							\
	}

#define PACKN(data, data_len)							\
	if (size >= len + data_len) {						\
		memcpy(buf + off, data, data_len);				\
		off += data_len;						\
	}									\
	len += data_len;

#define UNPACK8(out)								\
	if (size < sizeof(uint8_t)) {						\
		return false;							\
	}									\
	out = *buf++;								\
	--size;

#define UNPACKLE16(out)								\
	if (size < sizeof(uint16_t)) {						\
		return false;							\
	}									\
	out = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);			\
	buf += sizeof(uint16_t);						\
	size -= sizeof(uint16_t);

#define UNPACKLE32(out)								\
	if (size < sizeof(uint32_t)) {						\
		return false;							\
	}									\
	out = (uint32_t)buf[0]							\
	    | ((uint32_t)buf[1] << 8)						\
	    | ((uint32_t)buf[2] << 16)						\
	    | ((uint32_t)buf[3] << 24);						\
	buf += sizeof(uint32_t);						\
	size -= sizeof(uint32_t);

#define UNPACKLE64(out)								\
	if (size < sizeof(uint64_t)) {						\
		return false;							\
	}									\
	out = (uint64_t)buf[0]							\
	    | ((uint64_t)buf[1] << 8)						\
	    | ((uint64_t)buf[2] << 16)						\
	    | ((uint64_t)buf[3] << 24)						\
	    | ((uint64_t)buf[4] << 32)						\
	    | ((uint64_t)buf[5] << 40)						\
	    | ((uint64_t)buf[6] << 48)						\
	    | ((uint64_t)buf[7] << 56);						\
	buf += sizeof(uint64_t);						\
	size -= sizeof(uint64_t);

#define UNPACKCINT(out)								\
	if (size < 1) {								\
		return false;							\
	}									\
	switch (buf[0]) {							\
	case 0xfd:								\
		if (size < 3) {							\
			return false;						\
		}								\
		out = buf[1] | ((uint64_t)buf[2] << 8);				\
		buf += 3;							\
		size -= 3;							\
		break;								\
	case 0xfe:								\
		if (size < 5) {							\
			return false;						\
		}								\
		out = buf[1]							\
		    | ((uint64_t)buf[2] << 8)					\
		    | ((uint64_t)buf[3] << 16)					\
		    | ((uint64_t)buf[4] << 24);					\
		buf += 5;							\
		size -= 5;							\
		break;								\
	case 0xff:								\
		if (size < 9) {							\
			return false;						\
		}								\
		out = buf[1]							\
		    | ((uint64_t)buf[2] << 8)					\
		    | ((uint64_t)buf[3] << 16)					\
		    | ((uint64_t)buf[4] << 24)					\
		    | ((uint64_t)buf[5] << 32)					\
		    | ((uint64_t)buf[6] << 40)					\
		    | ((uint64_t)buf[7] << 48)					\
		    | ((uint64_t)buf[8] << 56);					\
		buf += 9;							\
		size -= 9;							\
		break;								\
	default:								\
		out = buf[0];							\
		buf += 1;							\
		size -= 1;							\
		break;								\
	}

#define UNPACKN(out, n)								\
	if (size < n) {								\
		return false;							\
	}									\
	memcpy(out, buf, n);							\
	buf += n;								\
	size -= n;

#endif
