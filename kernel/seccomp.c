/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Mode 1: fixed syscall list (original 3.4 implementation)
 * Mode 2: classic BPF filters, backported for Android 9 userspace.
 */

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/signal.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

/* #define SECCOMP_DEBUG 1 */

/*
 * Secure computing mode 1 allows only read/write/exit/sigreturn.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

#ifdef CONFIG_SECCOMP_FILTER
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

struct seccomp_filter {
	unsigned short len;
	struct seccomp_filter *prev;
	struct sock_filter insns[];
};

#define SECCOMP_MAX_INSNS	4096

/*
 * Classic BPF interpreter, subset sufficient for seccomp filters
 * (Android's bionic/seccomp policy uses LD/ABS, JMP and RET).
 */
static u32 seccomp_run_filter(const struct sock_filter *insns, unsigned short len,
			      const struct seccomp_data *sd)
{
	u32 A = 0, X = 0;
	u32 mem[BPF_MEMWORDS];
	unsigned int pc = 0;
	int i;

	for (i = 0; i < 65536; i++) {
		const struct sock_filter *f;

		if (pc >= len)
			return SECCOMP_RET_KILL;
		f = &insns[pc];

		switch (f->code) {
		case BPF_LD | BPF_W | BPF_ABS: {
			u32 off = f->k;
			if (off + 4 > sizeof(*sd) || (off & 3))
				return SECCOMP_RET_KILL;
			A = *(const u32 *)((const char *)sd + off);
			pc++;
			break;
		}
		case BPF_LD | BPF_IMM:
			A = f->k;
			pc++;
			break;
		case BPF_LDX | BPF_IMM:
			X = f->k;
			pc++;
			break;
		case BPF_LD | BPF_MEM:
			if (f->k >= BPF_MEMWORDS)
				return SECCOMP_RET_KILL;
			A = mem[f->k];
			pc++;
			break;
		case BPF_ST:
			if (f->k >= BPF_MEMWORDS)
				return SECCOMP_RET_KILL;
			mem[f->k] = A;
			pc++;
			break;
		case BPF_ALU | BPF_AND | BPF_K: A &= f->k; pc++; break;
		case BPF_ALU | BPF_OR  | BPF_K: A |= f->k; pc++; break;
		case BPF_ALU | BPF_ADD | BPF_K: A += f->k; pc++; break;
		case BPF_ALU | BPF_SUB | BPF_K: A -= f->k; pc++; break;
		case BPF_ALU | BPF_LSH | BPF_K: A <<= f->k; pc++; break;
		case BPF_ALU | BPF_RSH | BPF_K: A >>= f->k; pc++; break;
		case BPF_JMP | BPF_JA:
			pc += f->k + 1;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			pc += (A == f->k) ? f->jt + 1 : f->jf + 1;
			break;
		case BPF_JMP | BPF_JGT | BPF_K:
			pc += (A > f->k) ? f->jt + 1 : f->jf + 1;
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			pc += (A >= f->k) ? f->jt + 1 : f->jf + 1;
			break;
		case BPF_JMP | BPF_JSET | BPF_K:
			pc += (A & f->k) ? f->jt + 1 : f->jf + 1;
			break;
		case BPF_RET | BPF_K:
			return f->k;
		case BPF_MISC | BPF_TAX:
			X = A; pc++;
			break;
		case BPF_MISC | BPF_TXA:
			A = X; pc++;
			break;
		default:
			return SECCOMP_RET_KILL;
		}
	}
	return SECCOMP_RET_KILL;
}

static long seccomp_attach_filter(struct sock_fprog __user *fprog_user)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter;
	unsigned long total;
	int i;

	if (!fprog_user)
		return -EFAULT;
	if (copy_from_user(&fprog, fprog_user, sizeof(fprog)))
		return -EFAULT;
	if (fprog.len == 0 || fprog.len > SECCOMP_MAX_INSNS)
		return -EINVAL;

	total = sizeof(*filter) + fprog.len * sizeof(struct sock_filter);
	filter = kzalloc(total, GFP_KERNEL);
	if (!filter)
		return -ENOMEM;

	if (copy_from_user(filter->insns, fprog.filter,
			   fprog.len * sizeof(struct sock_filter))) {
		kfree(filter);
		return -EFAULT;
	}
	filter->len = fprog.len;

	/* basic validation: jump targets must stay inside the program */
	for (i = 0; i < filter->len; i++) {
		const struct sock_filter *f = &filter->insns[i];

		if (BPF_CLASS(f->code) == BPF_JMP &&
		    BPF_OP(f->code) != BPF_JA) {
			if (i + f->jt + 1 >= filter->len ||
			    i + f->jf + 1 >= filter->len) {
				kfree(filter);
				return -EINVAL;
			}
		}
	}

	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;
	current->seccomp.mode = SECCOMP_MODE_FILTER;
	set_thread_flag(TIF_SECCOMP);
	return 0;
}
#endif /* CONFIG_SECCOMP_FILTER */

void __secure_computing(int this_syscall)
{
	int mode = current->seccomp.mode;

	if (mode == SECCOMP_MODE_STRICT) {
		int *syscall = mode1_syscalls;

#ifdef CONFIG_COMPAT
		if (is_compat_task())
			syscall = mode1_syscalls_32;
#endif
		do {
			if (*syscall == this_syscall)
				return;
		} while (*++syscall);
	}
#ifdef CONFIG_SECCOMP_FILTER
	else if (mode == SECCOMP_MODE_FILTER) {
		struct pt_regs *regs = task_pt_regs(current);
		struct seccomp_data sd;
		struct seccomp_filter *f;
		u32 ret = SECCOMP_RET_ALLOW;
		int i;

		sd.nr = syscall_get_nr(current, regs);
		sd.arch = syscall_get_arch(current, regs);
		sd.instruction_pointer = instruction_pointer(regs);
		for (i = 0; i < 6; i++) {
			unsigned long arg = 0;

			syscall_get_arguments(current, regs, i, 1, &arg);
			sd.args[i] = arg;
		}

		for (f = current->seccomp.filter; f; f = f->prev)
			ret = seccomp_run_filter(f->insns, f->len, &sd);

		if ((ret & SECCOMP_RET_ACTION) == SECCOMP_RET_ALLOW)
			return;

		if ((ret & SECCOMP_RET_ACTION) == SECCOMP_RET_ERRNO) {
			int err = ret & SECCOMP_RET_DATA;

			syscall_set_return_value(current, regs, -err, regs->ARM_r0);
			return;
		}
		/* KILL / TRAP / TRACE: terminate */
		audit_seccomp(this_syscall);
		do_exit(SIGSYS);
	}
#endif
	else {
		BUG();
	}

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	audit_seccomp(this_syscall);
	do_exit(SIGKILL);
}

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	long ret;

	/* SECCOMP_MODE_FILTER filters may be stacked: Android installs the
	 * app filter first, then the WebView/Chromium sandbox installs its
	 * own.  Only strict mode is terminal. */
	ret = -EPERM;
	if (unlikely(current->seccomp.mode == SECCOMP_MODE_STRICT))
		goto out;
	if (unlikely(current->seccomp.mode == SECCOMP_MODE_FILTER &&
		     seccomp_mode != SECCOMP_MODE_FILTER))
		goto out;

	ret = -EINVAL;
	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		current->seccomp.mode = SECCOMP_MODE_STRICT;
		set_thread_flag(TIF_SECCOMP);
#ifdef TIF_NOTSC
		disable_TSC();
#endif
		ret = 0;
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER:
		ret = seccomp_attach_filter((struct sock_fprog __user *)filter);
		break;
#endif
	default:
		break;
	}

 out:
	return ret;
}
