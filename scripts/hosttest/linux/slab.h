#ifndef _FAKE_SLAB_H
#define _FAKE_SLAB_H
#include <linux/types.h>
#include <stdlib.h>
#define GFP_KERNEL 0
static inline void *kcalloc(size_t n, size_t sz, int f) { (void)f; return calloc(n, sz); }
static inline void *kmalloc(size_t sz, int f) { (void)f; return malloc(sz); }
static inline void *kzalloc(size_t sz, int f) { (void)f; return calloc(1, sz); }
static inline void *kmalloc_array(size_t n, size_t sz, int f) { (void)f; return calloc(n, sz); }
static inline void kfree(void *p) { free(p); }
#endif
