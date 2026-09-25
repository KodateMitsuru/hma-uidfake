#ifndef _FAKE_KERNEL_H
#define _FAKE_KERNEL_H
#include <linux/types.h>
#include <stdio.h>
#define READ_ONCE(x) (x)
#define pr_info(fmt, ...) fprintf(stderr, "[info] " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, "[warn] " fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)  fprintf(stderr, "[err ] " fmt, ##__VA_ARGS__)
static inline u32 ilog2(u32 x) { u32 r = 0; while (x >>= 1) r++; return r; }
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
