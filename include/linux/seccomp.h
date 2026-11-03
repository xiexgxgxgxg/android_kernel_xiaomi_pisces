#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <linux/types.h>

#ifdef CONFIG_SECCOMP

#include <linux/thread_info.h>
#include <asm/seccomp.h>

struct seccomp_filter;

typedef struct {
	int mode;
	struct seccomp_filter *filter;
} seccomp_t;

extern void __secure_computing(int);
static inline void secure_computing(int this_syscall)
{
	if (unlikely(test_thread_flag(TIF_SECCOMP)))
		__secure_computing(this_syscall);
}

extern long prctl_get_seccomp(void);
extern long prctl_set_seccomp(unsigned long arg2, char __user *filter);

static inline int seccomp_mode(seccomp_t *s)
{
	return s->mode;
}

#else /* CONFIG_SECCOMP */

#include <linux/errno.h>

typedef struct { } seccomp_t;

#define secure_computing(x) do { } while (0)

static inline long prctl_get_seccomp(void)
{
	return -EINVAL;
}

static inline long prctl_set_seccomp(unsigned long arg2, char __user *filter)
{
	return -EINVAL;
}

static inline int seccomp_mode(seccomp_t *s)
{
	return 0;
}

#endif /* CONFIG_SECCOMP */

/* mode definitions */
#define SECCOMP_MODE_DISABLED	0
#define SECCOMP_MODE_STRICT	1
#define SECCOMP_MODE_FILTER	2

/* return actions for SECCOMP_MODE_FILTER (classic BPF) */
#define SECCOMP_RET_KILL	0x00000000U
#define SECCOMP_RET_TRAP	0x00030000U
#define SECCOMP_RET_ERRNO	0x00050000U
#define SECCOMP_RET_TRACE	0x7ff00000U
#define SECCOMP_RET_ALLOW	0x7fff0000U

#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU

#endif /* _LINUX_SECCOMP_H */
