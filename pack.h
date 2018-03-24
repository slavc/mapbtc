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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

bool unpack_buf(uint8_t *p, size_t len, uint8_t **buf_ptr, size_t *buf_rem);
size_t unpack64(uint64_t *p, uint8_t *buf, size_t buf_size);
size_t unpack32(uint32_t *p, uint8_t *buf, size_t buf_size);
size_t unpack16(uint16_t *p, uint8_t *buf, size_t buf_size);
size_t unpack8(uint8_t *p, uint8_t *buf, size_t buf_size);
size_t unpack_cuint(uint64_t *p, uint8_t *buf, size_t buf_size);
size_t pack_buf(const void *ptr, size_t len, uint8_t *buf, size_t buf_size);
size_t pack64(uint64_t i, uint8_t *buf, size_t buf_size);
size_t pack32(uint32_t i, uint8_t *buf, size_t buf_size);
size_t pack16(uint16_t i, uint8_t *buf, size_t buf_size);
size_t pack8(uint8_t i, uint8_t *buf, size_t buf_size);
size_t pack_cuint(uint64_t i, uint8_t *buf, size_t buf_size);

#endif
