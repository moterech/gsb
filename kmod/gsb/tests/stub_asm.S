/*
 * Test stub: syscall gate, entry point, GSB brand note and "app" snippets.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <osreldate.h>

/* ---- GSB brand note (see gsb_abi.h) ---- */
	.section .note.gsb,"a",@note
	.p2align 2
	.long	4			/* n_namesz: "GSB\0" */
	.long	4			/* n_descsz */
	.long	1			/* n_type: GSB_NT_BRAND */
	.asciz	"GSB"
	.p2align 2
	.long	__FreeBSD_version

	.text

/* long gsb_syscall6(long nr, long a1..a6): -errno on failure. */
	.globl	gsb_syscall6
gsb_syscall6:
	movq	%rdi, %rax
	movq	%rsi, %rdi
	movq	%rdx, %rsi
	movq	%rcx, %rdx
	movq	%r8, %r10
	movq	%r9, %r8
	movq	8(%rsp), %r9
	.globl	gsb_gate
gsb_gate:
	syscall
	jb	1f
	ret
1:	negq	%rax
	ret

	.globl	_start
_start:
	/* FreeBSD passes the argc/argv block in %rdi; %rsp is realigned. */
	andq	$-16, %rsp
	call	stub_main
	ud2

/*
 * "App" code. It runs in app mode after the handler sigreturns into it.
 * The Linux exit syscall (60) hands %rdi back to the handler as the exit
 * status.
 */
#define	LINUX_EXIT	movq %rax, %rdi; movl $60, %eax; syscall; ud2

	.globl	app_getpid		/* T1: plain redirect */
app_getpid:
	movl	$39, %eax
	syscall
	LINUX_EXIT

	.globl	app_int80		/* T2: int 0x80 must redirect too */
app_int80:
	movl	$20, %eax		/* FreeBSD getpid */
	int	$0x80
	LINUX_EXIT

	.globl	app_jump_gate		/* T3: reuse the stub's syscall insn */
app_jump_gate:
	movl	$1, %eax		/* FreeBSD SYS_exit */
	movl	$7, %edi		/* exit(7) would mean it passed through */
	call	gsb_gate
	LINUX_EXIT

	.globl	app_sysenter		/* T4 */
app_sysenter:
	movl	$1, %eax
	movl	$7, %edi
	sysenter
	movl	$9, %eax
	LINUX_EXIT

	.globl	app_vsyscall		/* T5: legacy vsyscall page */
app_vsyscall:
	movq	$0xffffffffff600000, %rax
	call	*%rax
	movl	$9, %eax
	LINUX_EXIT

	.globl	app_regs		/* T11: Linux register semantics */
app_regs:
	movq	$0x1234, %r10
	xorl	%ecx, %ecx
	xorl	%r11d, %r11d
	movl	$39, %eax
	syscall
	cmpq	$0x1234, %r10		/* r10 must survive the round trip */
	je	1f
	movl	$52, %eax
1:	LINUX_EXIT
