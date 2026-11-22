/*
 * Round-trip spike: shared-memory protocol between the stub and a C
 * mini-Sentry. Mirrors the shape of gVisor systrap's sysmsg: one request
 * slot per stub thread, sequence counters, and _umtx_op wake-ups that are
 * skipped when the peer is spinning.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SPIKE_H_
#define	_SPIKE_H_

#include <stdint.h>

#define	SPIKE_SHM_FD	3		/* the stub inherits the shm here */
#define	SPIKE_SHM_SIZE	4096

enum spike_mode {
	SPIKE_LOCAL = 0,	/* stub answers getpid itself: kernel floor */
	SPIKE_SENTRY = 1,	/* full round trip through the Sentry */
};

struct spike_shm {
	/* stub -> Sentry */
	volatile uint32_t req_seq;
	volatile uint32_t sentry_sleeping;
	uint64_t nr;
	uint64_t args[6];

	/* Sentry -> stub */
	volatile uint32_t resp_seq;
	volatile uint32_t stub_sleeping;
	int64_t ret;

	/* configuration (Sentry -> stub, before start) */
	uint32_t spin;		/* spin iterations before sleeping */

	/* measurements (stub -> Sentry) */
	uint64_t tsc_first;	/* rdtsc at first redirected getpid */
	uint64_t tsc_last;	/* rdtsc at the app's exit */
	uint64_t ncalls;	/* getpid calls between the two */
	uint64_t nsleep_stub;	/* times the stub actually slept */
};

static inline uint64_t
spike_rdtsc(void)
{
	uint32_t lo, hi;

	__asm__ volatile("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

#endif
