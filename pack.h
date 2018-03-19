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
