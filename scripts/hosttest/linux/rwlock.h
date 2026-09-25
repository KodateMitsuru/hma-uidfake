#ifndef _FAKE_RWLOCK_H
#define _FAKE_RWLOCK_H
#include <linux/types.h>
typedef struct { int v; } rwlock_t;
#define read_lock_irqsave(l, f) do { (f) = 0; } while (0)
#define read_unlock_irqrestore(l, f) do { (void)(f); } while (0)
#define write_lock_irqsave(l, f) do { (f) = 0; } while (0)
#define write_unlock_irqrestore(l, f) do { (void)(f); } while (0)
#endif
