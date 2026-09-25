#ifndef _FAKE_MODULE_H
#define _FAKE_MODULE_H
#include <linux/types.h>
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define module_param_named(name, var, type, perm)
#define MODULE_PARM_DESC(name, desc)
#endif
