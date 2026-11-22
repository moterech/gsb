/*
 * gsb_abi.h: constants shared by the gsb kernel module, the stub and the Sentry.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GSB_ABI_H_
#define	_GSB_ABI_H_

/*
 * ELF branding of the stub binary.
 *
 * The stub carries a PT_NOTE with vendor "GSB" and type GSB_NT_BRAND whose
 * 4-byte descriptor is the FreeBSD osreldate it was built for. Its
 * EI_OSABI byte is set to GSB_ELFOSABI, which no in-tree brand claims, so
 * when gsb.ko is not loaded the stub fails to exec (ENOEXEC) instead of
 * silently running as a native FreeBSD process.
 */
#define	GSB_ABI_VENDOR		"GSB"
#define	GSB_NT_BRAND		1
#define	GSB_ELFOSABI		255	/* ELFOSABI_STANDALONE */

/* Name of the sysentvec, visible as kern.proc.sv_name / procstat -b. */
#define	GSB_SV_NAME		"GSB ELF64"

/*
 * SIGSYS delivered for a redirected syscall:
 *   si_signo  = SIGSYS
 *   si_code   = GSB_SI_SYSCALL
 *   si_trapno = syscall number (%rax at entry, truncated to 32 bits)
 *   si_addr   = %rip after the trapping instruction
 *
 * Register state in the delivered ucontext is fixed up to Linux post-syscall
 * semantics before the signal frame is built:
 *   mc_r10 = 4th argument, mc_rcx = %rip, mc_r11 = %rflags
 * (FreeBSD's syscall entry stores %r10 in the %rcx trapframe slot and does
 * not save %r10/%r11.) %rax still holds the syscall number.
 */
#define	GSB_SI_SYSCALL		1

#endif /* !_GSB_ABI_H_ */
