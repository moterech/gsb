/*
 * gsb: syscall redirection module for a gVisor-derived sandbox on FreeBSD.
 *
 * Every syscall issued by a process running under the GSB sysentvec is turned
 * into a synchronous SIGSYS for the user-space Sentry to handle, with one
 * exception: a short allowlist of FreeBSD syscalls ("passthrough") that the
 * stub itself needs. A call passes through only if ALL of these hold:
 *
 *   1. The thread is in stub mode: GSB_TDP2_APPMODE is clear. The bit is set
 *      only by a successful passthrough sigreturn(2), which is the only way
 *      into app code, and cleared only when a signal is delivered to the stub
 *      handler. App code therefore always runs with the bit set. Jumping into
 *      stub text does not change that.
 *   2. %rip - 2 lies inside the stub's text segment (vm_taddr/vm_tsize from
 *      the ELF loader).
 *   3. The two bytes before %rip are 0f 05 (`syscall`), not `int 0x80`.
 *   4. The full 64-bit %rax is a syscall on the allowlist, and the wrapper's
 *      argument checks pass. The wrappers copy arguments into the kernel
 *      once, so other threads cannot change them between check and use.
 *
 * Anything else goes to gsb_redirect(), which never runs a host syscall
 * implementation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/signalvar.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/thr.h>
#include <sys/ucontext.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/frame.h>
#include <machine/pcb.h>

#include "gsb_abi.h"

/*
 * Per-thread "app mode" flag in td_pflags2. Only curthread touches it, and
 * thread_alloc zeroes it for new threads (fork, thr_new), so new threads
 * start in stub mode at an entry point the stub chose.
 */
#define	GSB_TDP2_APPMODE	0x40000000
CTASSERT((GSB_TDP2_APPMODE & (TDP2_SBPAGES | TDP2_COMPAT32RB | TDP2_ACCT |
    TDP2_SAN_QUIET | TDP2_EXTERR | TDP2_UEXTERR)) == 0);

#define	GSB_IN_APP(td)	(((td)->td_pflags2 & GSB_TDP2_APPMODE) != 0)

extern struct sysentvec elf64_freebsd_sysvec_la48;
extern struct sysent sysent[];

/* ---------------------------------------------------------------- stats */

SDT_PROVIDER_DEFINE(gsb);
/* pid, syscall number, %rip */
SDT_PROBE_DEFINE3(gsb, , , redirect, "pid_t", "u_long", "uintptr_t");
SDT_PROBE_DEFINE3(gsb, , , passthrough, "pid_t", "u_long", "uintptr_t");
/* pid, syscall number, reason */
SDT_PROBE_DEFINE3(gsb, , , deny, "pid_t", "u_long", "const char *");
/* pid, signal, handler */
SDT_PROBE_DEFINE3(gsb, , , tostub, "pid_t", "int", "uintptr_t");
SDT_PROBE_DEFINE2(gsb, , , toapp, "pid_t", "uintptr_t");

static SYSCTL_NODE(_security, OID_AUTO, gsb, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "gVisor-derived sandbox syscall redirection");
static COUNTER_U64_DEFINE_EARLY(gsb_nredirect);
static COUNTER_U64_DEFINE_EARLY(gsb_npass);
static COUNTER_U64_DEFINE_EARLY(gsb_ndeny);
SYSCTL_COUNTER_U64(_security_gsb, OID_AUTO, redirects, CTLFLAG_RD,
    &gsb_nredirect, "Syscalls redirected to the Sentry as SIGSYS");
SYSCTL_COUNTER_U64(_security_gsb, OID_AUTO, passthroughs, CTLFLAG_RD,
    &gsb_npass, "Stub syscalls passed to the host");
SYSCTL_COUNTER_U64(_security_gsb, OID_AUTO, denials, CTLFLAG_RD,
    &gsb_ndeny, "Passthrough calls refused by argument checks");

#define	GSB_DENY(td, why) do {						\
	counter_u64_add(gsb_ndeny, 1);					\
	SDT_PROBE3(gsb, , , deny, (td)->td_proc->p_pid,			\
	    (u_long)(td)->td_sa.code, (why));				\
} while (0)

/* --------------------------------------------------------- stub ranges */

static bool
gsb_text_range(struct proc *p, uintptr_t *start, uintptr_t *end)
{
	struct vmspace *vm = p->p_vmspace;

	if (vm->vm_tsize == 0)
		return (false);
	*start = (uintptr_t)vm->vm_taddr;
	*end = *start + ptoa(vm->vm_tsize);
	return (*end > *start);
}

static bool
gsb_in_text(struct proc *p, uintptr_t va)
{
	uintptr_t s, e;

	return (gsb_text_range(p, &s, &e) && va >= s && va < e);
}

/*
 * Does [addr, addr+len) — rounded the way kern_mmap/kern_mprotect round it —
 * intersect the stub text? Overflowing ranges count as intersecting.
 */
static bool
gsb_hits_text(struct proc *p, uintptr_t addr, size_t len)
{
	uintptr_t s, e, a, end;

	if (!gsb_text_range(p, &s, &e))
		return (true);
	a = trunc_page(addr);
	end = addr + len;
	if (end < addr || round_page(end) < end)	/* overflow */
		return (true);
	end = round_page(end);
	return (a < e && end > s);
}

/* ------------------------------------------------------------ redirect */

static int
gsb_redirect(struct thread *td, void *uap __unused)
{
	struct trapframe *frame = td->td_frame;
	ksiginfo_t ksi;

	/*
	 * Restore Linux post-syscall register semantics; see gsb_abi.h.
	 * sendsig() sets PCB_FULL_IRET, so these reach the signal frame and,
	 * after sigreturn, user mode.
	 */
	frame->tf_r10 = frame->tf_rcx;
	frame->tf_rcx = frame->tf_rip;
	frame->tf_r11 = frame->tf_rflags;

	counter_u64_add(gsb_nredirect, 1);
	SDT_PROBE3(gsb, , , redirect, td->td_proc->p_pid,
	    (u_long)frame->tf_rax, (uintptr_t)frame->tf_rip);

	ksiginfo_init_trap(&ksi);
	ksi.ksi_signo = SIGSYS;
	ksi.ksi_code = GSB_SI_SYSCALL;
	ksi.ksi_trapno = (int)frame->tf_rax;
	ksi.ksi_addr = (void *)frame->tf_rip;
	/*
	 * If SIGSYS is not caught, or is blocked or ignored, trapsignal()
	 * kills the process (kern.forcesigexit), so the redirect fails closed.
	 */
	trapsignal(td, &ksi);

	/* Leave every register as sendsig() set it up. */
	return (EJUSTRETURN);
}

static struct sysent gsb_redirect_sysent = {
	.sy_narg = 0,
	.sy_call = (sy_call_t *)gsb_redirect,
	.sy_auevent = AUE_NULL,
	.sy_flags = SYF_CAPENABLED,	/* never ECAPMODE: always SIGSYS */
	.sy_thrcnt = SY_THR_STATIC,
};

/* -------------------------------------------------- passthrough wrappers */

static int
gsb_sys_mmap(struct thread *td, struct mmap_args *uap)
{
	if ((uap->flags & MAP_FIXED) != 0 &&
	    gsb_hits_text(td->td_proc, (uintptr_t)uap->addr, uap->len)) {
		GSB_DENY(td, "mmap over stub text");
		return (EPERM);
	}
	return (sys_mmap(td, uap));
}

static int
gsb_sys_munmap(struct thread *td, struct munmap_args *uap)
{
	if (gsb_hits_text(td->td_proc, (uintptr_t)uap->addr, uap->len)) {
		GSB_DENY(td, "munmap of stub text");
		return (EPERM);
	}
	return (sys_munmap(td, uap));
}

static int
gsb_sys_mprotect(struct thread *td, struct mprotect_args *uap)
{
	if (gsb_hits_text(td->td_proc, (uintptr_t)uap->addr, uap->len)) {
		GSB_DENY(td, "mprotect of stub text");
		return (EPERM);
	}
	return (sys_mprotect(td, uap));
}

static int
gsb_sys_madvise(struct thread *td, struct madvise_args *uap)
{
	if (gsb_hits_text(td->td_proc, (uintptr_t)uap->addr, uap->len)) {
		GSB_DENY(td, "madvise of stub text");
		return (EPERM);
	}
	return (sys_madvise(td, uap));
}

/* Handlers must live in stub text; mirrors sys_sigaction() otherwise. */
static int
gsb_sys_sigaction(struct thread *td, struct sigaction_args *uap)
{
	struct sigaction act, oact, *actp, *oactp;
	int error;

	actp = (uap->act != NULL) ? &act : NULL;
	oactp = (uap->oact != NULL) ? &oact : NULL;
	if (actp != NULL) {
		error = copyin(uap->act, actp, sizeof(act));
		if (error != 0)
			return (error);
		if (act.sa_handler != SIG_DFL && act.sa_handler != SIG_IGN &&
		    !gsb_in_text(td->td_proc, (uintptr_t)act.sa_handler)) {
			GSB_DENY(td, "sigaction handler outside stub text");
			return (EPERM);
		}
	}
	error = kern_sigaction(td, uap->sig, actp, oactp, 0);
	if (oactp != NULL && error == 0)
		error = copyout(oactp, uap->oact, sizeof(oact));
	return (error);
}

/* New threads start in stub mode, so their entry must be stub code. */
static int
gsb_sys_thr_new(struct thread *td, struct thr_new_args *uap)
{
	struct thr_param param;
	int error;

	if (uap->param_size < 0 || uap->param_size > sizeof(param))
		return (EINVAL);
	bzero(&param, sizeof(param));
	error = copyin(uap->param, &param, uap->param_size);
	if (error != 0)
		return (error);
	if (!gsb_in_text(td->td_proc, (uintptr_t)param.start_func)) {
		GSB_DENY(td, "thr_new start_func outside stub text");
		return (EPERM);
	}
	return (kern_thr_new(td, &param));
}

/* The only transition into app code. */
static int
gsb_sys_sigreturn(struct thread *td, struct sigreturn_args *uap)
{
	int error;

	error = sys_sigreturn(td, uap);
	if (error == EJUSTRETURN) {
		td->td_pflags2 |= GSB_TDP2_APPMODE;
		SDT_PROBE2(gsb, , , toapp, td->td_proc->p_pid,
		    (uintptr_t)td->td_frame->tf_rip);
	}
	return (error);
}

/*
 * Passthrough table, indexed by FreeBSD syscall number. Entries either
 * point at the native sysent (so syscall:freebsd:: DTrace probes still
 * fire) or at a gsb wrapper.
 */
static struct sysent gsb_wrap[SYS_MAXSYSCALL];
static struct sysent *gsb_pass[SYS_MAXSYSCALL];

static void
gsb_wrap_entry(int code, sy_call_t *fn)
{
	gsb_wrap[code] = sysent[code];		/* narg, flags, auevent */
	gsb_wrap[code].sy_call = fn;
	gsb_wrap[code].sy_entry = 0;
	gsb_wrap[code].sy_return = 0;
	gsb_wrap[code].sy_thrcnt = SY_THR_STATIC;
	gsb_pass[code] = &gsb_wrap[code];
}

static void
gsb_pass_init(void)
{
	static const int native[] = {
		SYS_exit,		/* stub/process teardown */
		SYS_thr_exit,
		SYS_thr_self,
		SYS__umtx_op,		/* Sentry <-> stub synchronisation */
		SYS_sigprocmask,
		SYS_sigaltstack,
		SYS_pdfork,		/* stub template spawns address spaces */
		SYS_cap_enter,
		SYS_recvmsg,		/* receive fds to map (SCM_RIGHTS) */
		SYS_close,
	};
	u_int i;

	for (i = 0; i < nitems(native); i++)
		gsb_pass[native[i]] = &sysent[native[i]];
	gsb_wrap_entry(SYS_mmap, (sy_call_t *)gsb_sys_mmap);
	gsb_wrap_entry(SYS_munmap, (sy_call_t *)gsb_sys_munmap);
	gsb_wrap_entry(SYS_mprotect, (sy_call_t *)gsb_sys_mprotect);
	gsb_wrap_entry(SYS_madvise, (sy_call_t *)gsb_sys_madvise);
	gsb_wrap_entry(SYS_sigaction, (sy_call_t *)gsb_sys_sigaction);
	gsb_wrap_entry(SYS_thr_new, (sy_call_t *)gsb_sys_thr_new);
	gsb_wrap_entry(SYS_sigreturn, (sy_call_t *)gsb_sys_sigreturn);

	for (i = 0; i < SYS_MAXSYSCALL; i++)
		KASSERT(gsb_pass[i] == NULL || gsb_pass[i]->sy_narg <= 6,
		    ("gsb: passthrough %u takes stack args", i));
}

static int
gsb_npassthrough(void)
{
	int i, n;

	for (i = n = 0; i < SYS_MAXSYSCALL; i++)
		n += (gsb_pass[i] != NULL);
	return (n);
}

/* ------------------------------------------------------------- dispatch */

static bool
gsb_may_pass(struct thread *td, struct trapframe *frame)
{
	uintptr_t rip = frame->tf_rip;

	if (GSB_IN_APP(td))
		return (false);
	if (frame->tf_rax >= SYS_MAXSYSCALL || gsb_pass[frame->tf_rax] == NULL)
		return (false);
	if (rip < 2 || !gsb_in_text(td->td_proc, rip - 2) ||
	    !gsb_in_text(td->td_proc, rip - 1))
		return (false);
	/* Reject int 0x80 (cd 80) landing in stub text: require 0f 05. */
	if (fuword16((const void *)(rip - 2)) != 0x050f)
		return (false);
	return (true);
}

static int
gsb_fetch_syscall_args(struct thread *td)
{
	struct trapframe *frame = td->td_frame;
	struct syscall_args *sa = &td->td_sa;

	sa->code = (u_int)frame->tf_rax;
	sa->original_code = sa->code;
	if (gsb_may_pass(td, frame)) {
		sa->callp = gsb_pass[frame->tf_rax];
		counter_u64_add(gsb_npass, 1);
		SDT_PROBE3(gsb, , , passthrough, td->td_proc->p_pid,
		    (u_long)frame->tf_rax, (uintptr_t)frame->tf_rip);
	} else {
		sa->callp = &gsb_redirect_sysent;
	}
	/* rdi, rsi, rdx, rcx(=r10), r8, r9 are contiguous in the trapframe. */
	memcpy(sa->args, &frame->tf_rdi, sizeof(sa->args[0]) * 6);
	td->td_retval[0] = 0;
	td->td_retval[1] = frame->tf_rdx;
	return (0);
}

/* Signals may only be delivered to stub-text handlers, and enter stub mode. */
static void
gsb_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	mtx_assert(&p->p_sigacts->ps_mtx, MA_OWNED);
	if (!gsb_in_text(p, (uintptr_t)catcher)) {
		mtx_unlock(&p->p_sigacts->ps_mtx);
		sigexit(td, SIGKILL);
		/* NOTREACHED */
	}
	sendsig(catcher, ksi, mask);
	td->td_pflags2 &= ~GSB_TDP2_APPMODE;
	SDT_PROBE3(gsb, , , tostub, p->p_pid, ksi->ksi_signo,
	    (uintptr_t)catcher);
}

/* ------------------------------------------------------- sysvec, brand */

static struct sysentvec gsb_sysvec;

static bool
gsb_trans_osrel(const Elf_Note *note, int32_t *osrel)
{
	uintptr_t p;

	p = (uintptr_t)(note + 1);
	p += roundup2(note->n_namesz, sizeof(Elf32_Addr));
	*osrel = *(const int32_t *)(p);
	return (true);
}

static Elf_Brandnote gsb_brandnote = {
	.hdr.n_namesz	= sizeof(GSB_ABI_VENDOR),
	.hdr.n_descsz	= sizeof(int32_t),
	.hdr.n_type	= GSB_NT_BRAND,
	.vendor		= GSB_ABI_VENDOR,
	.flags		= BN_TRANSLATE_OSREL,
	.trans_osrel	= gsb_trans_osrel,
};

static Elf64_Brandinfo gsb_brand = {
	.brand		= GSB_ELFOSABI,
	.machine	= EM_X86_64,
	.compat_3_brand	= NULL,
	.interp_path	= NULL,
	.sysvec		= &gsb_sysvec,
	.interp_newpath	= NULL,
	.brand_note	= &gsb_brandnote,
	.flags		= BI_BRAND_NOTE_MANDATORY | BI_BRAND_ONLY_STATIC,
};

static void
gsb_sysvec_init(void)
{
	/*
	 * Start from the native LA48 vector: it is already initialised
	 * (shared page, vdso, timekeep), and the stub is a FreeBSD-ABI
	 * program for every call that passes through.
	 */
	gsb_sysvec = elf64_freebsd_sysvec_la48;
	gsb_sysvec.sv_name = GSB_SV_NAME;
	gsb_sysvec.sv_table = sysent;	/* only used for names/limits */
	gsb_sysvec.sv_size = SYS_MAXSYSCALL;
	gsb_sysvec.sv_fetch_syscall_args = gsb_fetch_syscall_args;
	gsb_sysvec.sv_sendsig = gsb_sendsig;
	gsb_sysvec.sv_flags &= ~SV_SIGSYS;
	/* No core dumps: a stub's memory is the sandboxed app's memory. */
	gsb_sysvec.sv_coredump = NULL;
}

static int
gsb_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch (type) {
	case MOD_LOAD:
		gsb_pass_init();
		gsb_sysvec_init();
		if (elf64_insert_brand_entry(&gsb_brand) != 0) {
			printf("gsb: could not register ELF brand\n");
			return (EINVAL);
		}
		printf("gsb: loaded, %d passthrough syscalls\n",
		    gsb_npassthrough());
		return (0);
	case MOD_UNLOAD:
		if (elf64_brand_inuse(&gsb_brand))
			return (EBUSY);
		if (elf64_remove_brand_entry(&gsb_brand) != 0)
			return (EINVAL);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t gsb_mod = { "gsb", gsb_modevent, NULL };
DECLARE_MODULE(gsb, gsb_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_VERSION(gsb, 1);
