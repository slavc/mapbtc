#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/*
void f(void)
{
	uint8_t *buf_ptr = buf;
	size_t buf_rem = buf_len;

	success =
	    unpack_buf(&local_addr, 16, &buf_ptr, &buf_rem)
	    && unpack_buf(&remote_addr, 16, &buf_ptr, &buf_rem);
}
*/

// FIXME Network byte order in unpack functions

size_t unpack_cuint(uint64_t *p, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 1) {
		*p = 0;
		return 0;
	}

	switch (buf[0]) {
	case 0xfd:
		if (buf_size < 3) {
			*p = 0;
			return 0;
		}
		*p = buf[1]
		    | ((uint64_t)buf[2] << 8);
		return 3;
	case 0xfe:
		if (buf_size < 5) {
			*p = 0;
			return 0;
		}
		*p = buf[1]
		    | ((uint64_t)buf[2] << 8)
		    | ((uint64_t)buf[3] << 16)
		    | ((uint64_t)buf[4] << 24);
		return 5;
	case 0xff:
		if (buf_size < 9) {
			*p = 0;
			return 0;
		}
		*p = buf[1]
		    | ((uint64_t)buf[2] << 8)
		    | ((uint64_t)buf[3] << 16)
		    | ((uint64_t)buf[4] << 24)
		    | ((uint64_t)buf[5] << 32)
		    | ((uint64_t)buf[6] << 40)
		    | ((uint64_t)buf[7] << 48)
		    | ((uint64_t)buf[8] << 56);
		return 9;
	default:
		*p = buf[0];
		return 1;
	}
}

bool unpack_buf(uint8_t *p, size_t len, uint8_t **buf_ptr, size_t *buf_rem)
{
	if (*buf_rem < len) {
		return false;
	}
	memcpy(p, *buf_ptr, len);
	*buf_ptr += len;
	*buf_rem -= len;
	return true;
}

size_t unpack64(uint64_t *p, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 8) {
		return 0;
	}
	*p = (uint64_t)buf[0]
	    | ((uint64_t)buf[1] << 8)
	    | ((uint64_t)buf[2] << 16)
	    | ((uint64_t)buf[3] << 24)
	    | ((uint64_t)buf[4] << 32)
	    | ((uint64_t)buf[5] << 40)
	    | ((uint64_t)buf[6] << 48)
	    | ((uint64_t)buf[7] << 56);
	return 8;
}

size_t unpack32(uint32_t *p, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 4) {
		return 0;
	}
	*p = (uint32_t)buf[0]
	    | ((uint32_t)buf[1] << 8)
	    | ((uint32_t)buf[2] << 16)
	    | ((uint32_t)buf[3] << 24);
	return 4;
}

size_t unpack16(uint16_t *p, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 2) {
		return 0;
	}
	*p = (uint16_t)buf[0]
	    | ((uint16_t)buf[1] << 8);
	return 2;
}

size_t unpack8(uint8_t *p, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 1) {
		return 0;
	}
	*p = buf[0];
	return 1;
}

size_t pack_buf(const void *ptr, size_t len, uint8_t *buf, size_t buf_size)
{
	if (buf_size < len) {
		return 0;
	}
	memcpy(buf, ptr, len);
	return len;
}

size_t pack64(uint64_t i, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 8) {
		return 0;
	}
	buf[0] = i;
	buf[1] = i >> 8;
	buf[2] = i >> 16;
	buf[3] = i >> 24;
	buf[4] = i >> 32;
	buf[5] = i >> 40;
	buf[6] = i >> 48;
	buf[7] = i >> 56;
	return 8;
}

size_t pack32(uint32_t i, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 4) {
		return 0;
	}
	buf[0] = i;
	buf[1] = i >> 8;
	buf[2] = i >> 16;
	buf[3] = i >> 24;
	return 4;
}

size_t pack16(uint16_t i, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 2) {
		return 0;
	}
	buf[0] = i;
	buf[1] = i >> 8;
	return 2;
}

size_t pack8(uint8_t i, uint8_t *buf, size_t buf_size)
{
	if (buf_size < 1) {
		return 0;
	}
	buf[0] = i;
	return 1;
}

size_t pack_cuint(uint64_t i, uint8_t *buf, size_t buf_size)
{
	size_t len;

	if (i <= 252) {
		len = 1;
	} else if (i <= 0xffff) {
		len = 3;
	} else if (i <= 0xffffffff) {
		len = 5;
	} else if (i <= 0xffffffffffffffff) {
		len = 9;
	} else {
		return 0;
	}

	if (buf_size < len) {
		return 0;
	}
	switch (len) {
	case 1:
		buf[0] = i;
		break;
	case 3:
		buf[0] = 0xfd;
		buf[1] = i;
		buf[2] = i >> 8;
		break;
	case 5:
		buf[0] = 0xfe;
		buf[1] = i;
		buf[2] = i >> 8;
		buf[3] = i >> 16;
		buf[4] = i >> 24;
		break;
	case 9:
		buf[0] = 0xff;
		buf[1] = i;
		buf[2] = i >> 8;
		buf[3] = i >> 16;
		buf[4] = i >> 24;
		buf[5] = i >> 32;
		buf[6] = i >> 49;
		buf[7] = i >> 48;
		buf[8] = i >> 56;
		break;
	}
	return len;
}
