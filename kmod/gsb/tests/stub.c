/*
 * Freestanding test stub for gsb.ko. It plays both roles: the stub (its
 * SIGSYS handler) and the Sentry (it decides results in that handler).
 * Each test reports through the process exit status; run_tests.sh holds
 * the expected values.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/thr.h>
#include <sys/ucontext.h>
#include <errno.h>

#include "../gsb_abi.h"

long gsb_syscall6(long, long, long, long, long, long, long);
#define	SC(n, a, b, c, d, e, f)	gsb_syscall6((n), (long)(a), (long)(b), \
	(long)(c), (long)(d), (long)(e), (long)(f))

extern char _start[], gsb_gate[];
extern char app_getpid[], app_int80[], app_jump_gate[], app_sysenter[],
    app_vsyscall[], app_regs[];

#define	NR_ENTER	9999	/* unlisted number used to get a first ucontext */
#define	LINUX_GETPID	39
#define	LINUX_EXIT	60

static int test;
static volatile int phase;	/* 0: stub, 1: app entered */
static char *app_entry;
static char altstack[64 * 1024] __attribute__((aligned(16)));
static char appstack[64 * 1024] __attribute__((aligned(16)));

void *memset(void *d, int c, size_t n)
{ unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n)
{ unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }

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

static void
handler(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;
	mcontext_t *mc = &uc->uc_mcontext;

	if (sig != SIGSYS) {
		if (test == 5)
			die(si->si_addr == (void *)0xffffffffff600000UL ? 111 : 112);
		die(100 + sig);
	}
	if (si->si_code != GSB_SI_SYSCALL)
		die(98);

	if (phase == 0) {
		if (test == 6 && si->si_trapno == SYS_exit)
			die(45);	/* stub-mode syscall outside text redirected */
		if (si->si_trapno != NR_ENTER)
			die(97);
		phase = 1;
		mc->mc_rip = (register_t)app_entry;
		mc->mc_rsp = (register_t)(appstack + sizeof(appstack) - 64);
		resume(uc);
	}

	switch (si->si_trapno) {
	case LINUX_EXIT:
		die((int)mc->mc_rdi);
	case LINUX_GETPID:
		if (test == 11) {
			if (mc->mc_r10 != 0x1234 || mc->mc_rcx != mc->mc_rip ||
			    mc->mc_r11 != mc->mc_rflags)
				die(51);
			mc->mc_rax = 50;
		} else {
			mc->mc_rax = 42;
		}
		break;
	case 20:			/* int 0x80 getpid */
		mc->mc_rax = 43;
		break;
	case SYS_exit:			/* app reused the stub gate */
		mc->mc_rax = 44;
		break;
	default:
		die(96);
	}
	resume(uc);
}

/* An RX page outside the stub's text containing `code`. */
static char *
foreign_code(const unsigned char *code, size_t len)
{
	long p;

	p = SC(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (p < 0 && p > -4096)
		die(90);
	memcpy((void *)p, code, len);
	if (SC(SYS_mprotect, p, 4096, PROT_READ | PROT_EXEC, 0, 0, 0) != 0)
		die(91);
	return ((char *)p);
}

static void
install(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	memset(&sa.sa_mask, 0xff, sizeof(sa.sa_mask));
	if (SC(SYS_sigaction, sig, &sa, 0, 0, 0, 0) != 0)
		die(92);
}

static void
setup(void)
{
	stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack) };

	if (SC(SYS_sigaltstack, &ss, 0, 0, 0, 0, 0) != 0)
		die(93);
	install(SIGSYS);
	install(SIGSEGV);
	install(SIGBUS);
	install(SIGILL);
	install(SIGTRAP);
}

static void
enter_app(char *entry)
{
	app_entry = entry;
	SC(NR_ENTER, 0, 0, 0, 0, 0, 0);	/* -> SIGSYS -> handler -> app */
	die(94);
}

void
stub_main(long *sp)
{
	char **argv = (char **)(sp + 1);
	const char *s;
	long r;

	for (s = sp[0] > 1 ? argv[1] : ""; *s >= '0' && *s <= '9'; s++)
		test = test * 10 + (*s - '0');

	if (test == 9) {
		/* No handler: a redirected call must kill us with SIGSYS. */
		SC(NR_ENTER, 0, 0, 0, 0, 0, 0);
		die(1);
	}
	if (test == 99) {
		/* Park in stub mode so the runner can inspect us. */
		for (;;)
			__asm__ volatile("pause");
	}
	setup();

	switch (test) {
	case 1: enter_app(app_getpid);
	case 2: enter_app(app_int80);
	case 3: enter_app(app_jump_gate);
	case 4: enter_app(app_sysenter);
	case 5: enter_app(app_vsyscall);
	case 6: {
		/* Stub mode, but the syscall insn is outside stub text. */
		static const unsigned char code[] = {
			0xb8, 0x01, 0, 0, 0,	/* mov $SYS_exit, %eax */
			0xbf, 0x07, 0, 0, 0,	/* mov $7, %edi */
			0x0f, 0x05,		/* syscall */
			0xc3,			/* ret */
		};
		((void (*)(void))foreign_code(code, sizeof(code)))();
		die(1);
	}
	case 7: {
		/* No remapping or reprotecting stub text. */
		long text = (long)_start & ~4095L;

		r = SC(SYS_mmap, text, 4096, PROT_READ | PROT_WRITE,
		    MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
		if (r != -EPERM)
			die(1);
		if (SC(SYS_mprotect, text, 4096, PROT_READ | PROT_WRITE,
		    0, 0, 0) != -EPERM)
			die(2);
		if (SC(SYS_munmap, text, 4096, 0, 0, 0, 0) != -EPERM)
			die(3);
		die(46);
	}
	case 8: {
		/* Host signal handlers must be stub code. */
		static const unsigned char ret[] = { 0xc3 };
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = (void (*)(int))foreign_code(ret, 1);
		die(SC(SYS_sigaction, SIGUSR1, &sa, 0, 0, 0, 0) == -EPERM ?
		    47 : 1);
	}
	case 10: {
		/* New threads must start in stub code. */
		static const unsigned char ret[] = { 0xc3 };
		struct thr_param tp;
		long tid;

		memset(&tp, 0, sizeof(tp));
		tp.start_func = (void (*)(void *))foreign_code(ret, 1);
		tp.stack_base = appstack;
		tp.stack_size = sizeof(appstack);
		tp.child_tid = &tid;
		tp.parent_tid = &tid;
		die(SC(SYS_thr_new, &tp, sizeof(tp), 0, 0, 0, 0) == -EPERM ?
		    48 : 1);
	}
	case 11: enter_app(app_regs);
	case 12: {
		/* App mode, syscall from app memory (outside stub text). */
		static const unsigned char code[] = {
			0xb8, 0x01, 0, 0, 0,	/* mov $SYS_exit, %eax */
			0xbf, 0x07, 0, 0, 0,	/* mov $7, %edi */
			0x0f, 0x05,		/* syscall */
			0x48, 0x89, 0xc7,	/* mov %rax, %rdi */
			0xb8, 0x3c, 0, 0, 0,	/* mov $60, %eax */
			0x0f, 0x05,		/* syscall */
			0x0f, 0x0b,		/* ud2 */
		};
		enter_app(foreign_code(code, sizeof(code)));
	}
	}
	die(127);
}
