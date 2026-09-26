#ifndef _FAKE_SPINLOCK_H
#define _FAKE_SPINLOCK_H
#include <linux/types.h>
/* host-test shim: single-threaded; the irq state is whatever the caller had */
typedef struct {
	int locked;
} spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x = {0}
#define spin_lock(l)                                                                               \
	do {                                                                                       \
		(void)(l);                                                                         \
	} while (0)
#define spin_unlock(l)                                                                             \
	do {                                                                                       \
		(void)(l);                                                                         \
	} while (0)
#define spin_lock_irqsave(l, f)                                                                    \
	do {                                                                                       \
		(void)(l);                                                                         \
		(f) = 0;                                                                           \
	} while (0)
#define spin_unlock_irqrestore(l, f)                                                               \
	do {                                                                                       \
		(void)(l);                                                                         \
		(void)(f);                                                                         \
	} while (0)
#endif
