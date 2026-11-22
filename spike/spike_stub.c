/*
 * Spike stub. Runs under gsb.ko. Its SIGSYS handler forwards each
 * redirected app syscall to the Sentry over shared memory (SPIKE_SENTRY),
 * or answers getpid itself (SPIKE_LOCAL) to measure the kernel-only floor.
 *
 *   spike_stub <mode> <iterations>      (shm inherited on fd 3)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/umtx.h>

#include "../kmod/gsb/gsb_abi.h"
#include "spike.h"

long gsb_syscall6(long, long, long, long, long, long, long);
#define	SC(n, a, b, c, d, e, f)	gsb_syscall6((n), (long)(a), (long)(b), \
	(long)(c), (long)(d), (long)(e), (long)(f))

extern char app_loop[];

#define	NR_ENTER	9999
#define	LINUX_GETPID	39
#define	LINUX_EXIT	60
#define	LINUX_ENOSYS	38

static int mode;
static long iters;
static int entered;
static uint64_t count;
static struct spike_shm *shm;
static char altstack[64 * 1024] __attribute__((aligned(16)));
static char appstack[64 * 1024] __attribute__((aligned(16)));

void *memset(void *d, int c, size_t n)
{ unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }

static __attribute__((noreturn)) void
die(int code)
{
	for (;;)
		SC(SYS_exit, code, 0, 0, 0, 0, 0);
}

static __attribute__((noreturn)) void
resume(ucontext_t *uc)
{
	SC(SYS_sigreturn, uc, 0, 0, 0, 0, 0);
	die(95);
}

static long
parse(const char *s)
{
	long v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (*s++ - '0');
	return (v);
}

/* Send the current request; spin, then sleep, until the Sentry answers. */
static int64_t
call_sentry(uint64_t nr, const mcontext_t *mc)
{
	uint32_t want;
	uint32_t i;

	shm->nr = nr;
	shm->args[0] = mc->mc_rdi;
	shm->args[1] = mc->mc_rsi;
	shm->args[2] = mc->mc_rdx;
	shm->args[3] = mc->mc_r10;
	shm->args[4] = mc->mc_r8;
	shm->args[5] = mc->mc_r9;
	want = __atomic_load_n(&shm->resp_seq, __ATOMIC_RELAXED) + 1;
	__atomic_add_fetch(&shm->req_seq, 1, __ATOMIC_SEQ_CST);
	if (__atomic_load_n(&shm->sentry_sleeping, __ATOMIC_SEQ_CST))
		SC(SYS__umtx_op, &shm->req_seq, UMTX_OP_WAKE, 1, 0, 0, 0);

	for (i = 0; i < shm->spin; i++) {
		if (__atomic_load_n(&shm->resp_seq, __ATOMIC_ACQUIRE) == want)
			return (shm->ret);
		__asm__ volatile("pause");
	}
	for (;;) {
		__atomic_store_n(&shm->stub_sleeping, 1, __ATOMIC_SEQ_CST);
		if (__atomic_load_n(&shm->resp_seq, __ATOMIC_SEQ_CST) == want)
			break;
		shm->nsleep_stub++;
		SC(SYS__umtx_op, &shm->resp_seq, UMTX_OP_WAIT_UINT, want - 1,
		    0, 0, 0);
		if (__atomic_load_n(&shm->resp_seq, __ATOMIC_SEQ_CST) == want)
			break;
	}
	__atomic_store_n(&shm->stub_sleeping, 0, __ATOMIC_SEQ_CST);
	return (shm->ret);
}

static void
handler(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;
	mcontext_t *mc = &uc->uc_mcontext;
	uint64_t nr;

	if (sig != SIGSYS || si->si_code != GSB_SI_SYSCALL)
		die(100 + sig);
	nr = (uint64_t)mc->mc_rax;	/* full 64-bit syscall number */

	if (!entered) {
		if (nr != NR_ENTER)
			die(97);
		entered = 1;
		mc->mc_rip = (register_t)app_loop;
		mc->mc_rdi = iters;
		mc->mc_rsp = (register_t)(appstack + sizeof(appstack) - 64);
		resume(uc);
	}

	if (count++ == 0)
		shm->tsc_first = spike_rdtsc();
	if (nr == LINUX_EXIT) {
		shm->tsc_last = spike_rdtsc();
		shm->ncalls = count - 1;
		if (mode == SPIKE_SENTRY)
			(void)call_sentry(nr, mc);
		die((int)mc->mc_rdi);
	}

	if (mode == SPIKE_LOCAL)
		mc->mc_rax = (nr == LINUX_GETPID) ? 1 : -LINUX_ENOSYS;
	else
		mc->mc_rax = call_sentry(nr, mc);
	resume(uc);
}

void
stub_main(long *sp)
{
	char **argv = (char **)(sp + 1);
	struct sigaction sa;
	stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack) };
	long p;

	if (sp[0] < 3)
		die(2);
	mode = (int)parse(argv[1]);
	iters = parse(argv[2]);
	if (iters < 1)
		die(2);

	p = SC(SYS_mmap, 0, SPIKE_SHM_SIZE, PROT_READ | PROT_WRITE,
	    MAP_SHARED, SPIKE_SHM_FD, 0);
	if (p < 0 && p > -4096)
		die(90);
	shm = (struct spike_shm *)p;

	if (SC(SYS_sigaltstack, &ss, 0, 0, 0, 0, 0) != 0)
		die(93);
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	memset(&sa.sa_mask, 0xff, sizeof(sa.sa_mask));
	if (SC(SYS_sigaction, SIGSYS, &sa, 0, 0, 0, 0) != 0)
		die(92);

	SC(NR_ENTER, 0, 0, 0, 0, 0, 0);	/* SIGSYS -> handler -> app_loop */
	die(94);
}
