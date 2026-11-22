/*
 * Baseline for the spike: the stock FreeBSD path for
 * syscall -> SIGSYS -> handler -> sigreturn (nosys, no gsb.ko involved).
 * SPDX-License-Identifier: Apache-2.0
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile long hits;
static void h(int s, siginfo_t *si, void *c) { (void)s; (void)si; (void)c; hits++; }

int
main(int argc, char **argv)
{
	struct sigaction sa = { .sa_sigaction = h, .sa_flags = SA_SIGINFO };
	struct timespec a, b;
	long n = argc > 1 ? atol(argv[1]) : 20000, i;

	sigfillset(&sa.sa_mask);
	sigaction(SIGSYS, &sa, NULL);
	clock_gettime(CLOCK_MONOTONIC, &a);
	for (i = 0; i < n; i++)
		syscall(9999);		/* nosys -> SIGSYS */
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("native nosys SIGSYS     %9.0f ns/call (%ld signals)\n",
	    ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / n, hits);
	return (0);
}
