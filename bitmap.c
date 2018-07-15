#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

struct bm {
	size_t size; /* number of bits */
	unsigned long bits[];
};

struct bm *bm_alloc(size_t num_bits)
{
	size_t q = num_bits / (sizeof(unsigned long) * CHAR_BIT);
	size_t r = num_bits % (sizeof(unsigned long) * CHAR_BIT);

	size_t size = (1 + q + !!r) * sizeof(unsigned long);
	struct bm *bm = calloc(1, size);

	printf("allocated %lu bytes in total (q=%lu, r=%lu)\n", size, q, r);

	bm->size = num_bits;

	return bm;
}

void bm_set(struct bm *bm, size_t i)
{
	assert(bm != NULL);
	assert(i < bm->size);
	size_t q, r;
	q = i / (sizeof(unsigned long) * CHAR_BIT);
	r = i % (sizeof(unsigned long) * CHAR_BIT);
	printf("setting in word %lu, offset %lu\n", q, r);
	bm->bits[q] |= (1ul << r);
}

bool bm_test(struct bm *bm, size_t i)
{
	assert(bm != NULL);
	assert(i < bm->size);
	size_t q, r;
	q = i / (sizeof(unsigned long) * CHAR_BIT);
	r = i % (sizeof(unsigned long) * CHAR_BIT);
	printf("testing bit %lu in word %lu, offset %lu (%d)\n", i, q, r, (int)!!(bm->bits[q] & (1ul << r)));
	return bm->bits[q] & (1ul << r);
}

struct bm *bm_clone(struct bm *orig)
{
	struct bm *copy = bm_alloc(orig->size);

	size_t q = orig->size / sizeof(unsigned long);
	size_t r = orig->size % sizeof(unsigned long);

	memcpy(copy, orig, sizeof(unsigned long) * (q + !!r));

	return copy;
}

#ifdef UNITTEST
#undef NDEBUG
#define bitmap_unittest main
int bitmap_unittest(int argc, char **argv)
{
	struct bm *bm;

	bm = bm_alloc(9);
	free(bm);

	bm = bm_alloc(8);
	free(bm);

	bm = bm_alloc(7);
	bm_set(bm, 0);
	assert(bm_test(bm, 0));
	assert(!bm_test(bm, 6));
	free(bm);

	bm = bm_alloc(17);
	bm_set(bm, 0);
	assert(bm_test(bm, 0));
	assert(!bm_test(bm, 6));
	assert(!bm_test(bm, 16));
	free(bm);

	bm = bm_alloc(sizeof(unsigned long) * CHAR_BIT);
	bm_set(bm, 0);
	assert(bm_test(bm, 0));
	assert(!bm_test(bm, 6));
	assert(!bm_test(bm, sizeof(unsigned long) * CHAR_BIT - 1));
	free(bm);

	return 0;
}
#endif // UNITTEST
