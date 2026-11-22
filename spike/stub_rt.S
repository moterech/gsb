/*
 * Spike stub runtime: GSB brand note, syscall gate, entry, and the "app".
 * SPDX-License-Identifier: Apache-2.0
 */
#include <osreldate.h>

	.section .note.gsb,"a",@note
	.p2align 2
	.long	4, 4, 1
	.asciz	"GSB"
	.p2align 2
	.long	__FreeBSD_version

	.text
	.globl	gsb_syscall6
gsb_syscall6:
	movq	%rdi, %rax
	movq	%rsi, %rdi
	movq	%rdx, %rsi
	movq	%rcx, %rdx
	movq	%r8, %r10
	movq	%r9, %r8
	movq	8(%rsp), %r9
	syscall
	jb	1f
	ret
1:	negq	%rax
	ret

	.globl	_start
_start:
	andq	$-16, %rsp		/* argc/argv block is in %rdi */
	call	stub_main
	ud2

/*
 * The "app": a Linux getpid loop, as a static Linux binary would issue it.
 * %rdi = iteration count. %rbx survives every round trip because sigreturn
 * restores the full context.
 */
	.globl	app_loop
app_loop:
	movq	%rdi, %rbx
1:	movl	$39, %eax		/* Linux getpid */
	syscall
	decq	%rbx
	jnz	1b
	xorl	%edi, %edi
	movl	$60, %eax		/* Linux exit */
	syscall
	ud2
