/*
 * ARM syscall helpers for seccomp filter (backport).
 */
#ifndef _ASM_ARM_SYSCALL_H
#define _ASM_ARM_SYSCALL_H

#include <linux/err.h>
#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <asm/elf.h>
#include <linux/audit.h>

static inline int syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->ARM_r7;
}

static inline void syscall_rollback(struct task_struct *task, struct pt_regs *regs)
{
	/* nothing */
}

static inline long syscall_get_error(struct task_struct *task, struct pt_regs *regs)
{
	return regs->ARM_r0;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->ARM_r0;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	regs->ARM_r0 = (long)error ? error : val;
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
	unsigned long *r = &regs->ARM_r0;

	while (n--)
		*args++ = r[i++];
}

static inline int syscall_get_arch(struct task_struct *task,
				   struct pt_regs *regs)
{
	return AUDIT_ARCH_ARM;
}

#endif /* _ASM_ARM_SYSCALL_H */
