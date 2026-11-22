/*
 * C mini-Sentry for the round-trip spike. Spawns the stub with a shared SHM_ANON
 * page on fd 3, serves its redirected syscalls (getpid -> 1, exit), and
 * reports per-call round-trip latency next to two baselines:
 *
 *   native  : FreeBSD getpid(2) in a loop (host syscall cost)
 *   local   : app syscall -> gsb.ko SIGSYS -> stub handler -> sigreturn
 *             (the kernel floor, no Sentry involved)
 *   sentry  : local + shm request/response with the Sentry process
 *
 *   sentry [-n iterations] [-s spin] [-r repeats] path/to/spike_stub
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/umtx.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "spike.h"

#define	LINUX_GETPID	39
#define	LINUX_EXIT	60
#define	LINUX_ENOSYS	38

extern char **environ;

static double tsc_per_ns;

static uint64_t
now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

static void
calibrate(void)
{
	uint64_t t0, t1, c0, c1;

	t0 = now_ns();
	c0 = spike_rdtsc();
	usleep(200000);
	t1 = now_ns();
	c1 = spike_rdtsc();
	tsc_per_ns = (double)(c1 - c0) / (double)(t1 - t0);
}

static double
native_getpid(long n)
{
	uint64_t t0, t1;
	long i;

	t0 = now_ns();
	for (i = 0; i < n; i++)
		(void)syscall(SYS_getpid);	/* not libc-cached */
	t1 = now_ns();
	return ((double)(t1 - t0) / n);
}

static void
serve(struct spike_shm *shm)
{
	uint32_t seen = 0, i;

	for (;;) {
		/* Wait for req_seq to move past `seen`: spin, then sleep. */
		for (i = 0; i < shm->spin; i++) {
			if (__atomic_load_n(&shm->req_seq, __ATOMIC_ACQUIRE) != seen)
				goto got;
			__asm__ volatile("pause");
		}
		for (;;) {
			__atomic_store_n(&shm->sentry_sleeping, 1, __ATOMIC_SEQ_CST);
			if (__atomic_load_n(&shm->req_seq, __ATOMIC_SEQ_CST) != seen)
				break;
			if (_umtx_op(__DEVOLATILE(void *, &shm->req_seq),
			    UMTX_OP_WAIT_UINT, seen, NULL, NULL) == -1 &&
			    errno != EINTR)
				err(1, "_umtx_op wait");
			if (__atomic_load_n(&shm->req_seq, __ATOMIC_SEQ_CST) != seen)
				break;
		}
		__atomic_store_n(&shm->sentry_sleeping, 0, __ATOMIC_SEQ_CST);
got:
		seen++;
		switch (shm->nr) {
		case LINUX_GETPID:
			shm->ret = 1;		/* pid inside the sandbox */
			break;
		case LINUX_EXIT:
			shm->ret = 0;
			break;
		default:
			shm->ret = -LINUX_ENOSYS;
		}
		__atomic_add_fetch(&shm->resp_seq, 1, __ATOMIC_SEQ_CST);
		if (__atomic_load_n(&shm->stub_sleeping, __ATOMIC_SEQ_CST))
			_umtx_op(__DEVOLATILE(void *, &shm->resp_seq),
			    UMTX_OP_WAKE, 1, NULL, NULL);
		if (shm->nr == LINUX_EXIT)
			return;
	}
}

/* Run the stub once; returns ns per redirected call. */
static double
run_stub(const char *stub, int mode, long n, uint32_t spin,
    uint64_t *nsleep)
{
	posix_spawn_file_actions_t fa;
	struct spike_shm *shm;
	char modes[16], ns[32];
	char *argv[] = { (char *)stub, modes, ns, NULL };
	pid_t pid;
	int fd, status;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	if (fd == -1 || ftruncate(fd, SPIKE_SHM_SIZE) == -1)
		err(1, "shm");
	shm = mmap(NULL, SPIKE_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0);
	if (shm == MAP_FAILED)
		err(1, "mmap");
	memset(shm, 0, sizeof(*shm));
	shm->spin = spin;

	snprintf(modes, sizeof(modes), "%d", mode);
	snprintf(ns, sizeof(ns), "%ld", n);
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, fd, SPIKE_SHM_FD);
	if ((errno = posix_spawn(&pid, stub, &fa, NULL, argv, environ)) != 0)
		err(1, "spawn %s", stub);
	posix_spawn_file_actions_destroy(&fa);

	if (mode == SPIKE_SENTRY)
		serve(shm);
	if (waitpid(pid, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "stub failed: %s %d", WIFSIGNALED(status) ?
		    "signal" : "exit", WIFSIGNALED(status) ?
		    WTERMSIG(status) : WEXITSTATUS(status));
	if (shm->ncalls != (uint64_t)n)
		errx(1, "stub saw %ju calls, want %ld", (uintmax_t)shm->ncalls, n);

	*nsleep = shm->nsleep_stub;
	double r = (double)(shm->tsc_last - shm->tsc_first) / tsc_per_ns / n;
	munmap(shm, SPIKE_SHM_SIZE);
	close(fd);
	return (r);
}

static int
cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return ((x > y) - (x < y));
}

static void
report(const char *name, double *v, int r, const char *extra)
{
	qsort(v, r, sizeof(*v), cmp);
	printf("%-22s median %9.0f ns   min %9.0f ns   max %9.0f ns  %s\n",
	    name, v[r / 2], v[0], v[r - 1], extra);
}

int
main(int argc, char **argv)
{
	long n = 20000;
	int r = 5, ch, i;
	uint32_t spins[] = { 0, 20000 };
	double v[64];
	uint64_t nsleep;
	char extra[64];

	while ((ch = getopt(argc, argv, "n:r:")) != -1) {
		switch (ch) {
		case 'n': n = strtol(optarg, NULL, 10); break;
		case 'r': r = atoi(optarg); break;
		default: errx(2, "usage: sentry [-n iters] [-r repeats] stub");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 || r < 1 || r > 64 || n < 1)
		errx(2, "usage: sentry [-n iters] [-r repeats] stub");

	calibrate();
	printf("tsc %.3f GHz, %ld calls x %d runs\n", tsc_per_ns, n, r);

	for (i = 0; i < r; i++)
		v[i] = native_getpid(n);
	report("native getpid", v, r, "");

	for (i = 0; i < r; i++)
		v[i] = run_stub(argv[0], SPIKE_LOCAL, n, 0, &nsleep);
	report("redirect, local", v, r, "(SIGSYS+sigreturn only)");

	for (size_t s = 0; s < sizeof(spins) / sizeof(spins[0]); s++) {
		char name[32];
		uint64_t sl = 0;

		for (i = 0; i < r; i++) {
			v[i] = run_stub(argv[0], SPIKE_SENTRY, n, spins[s],
			    &nsleep);
			sl += nsleep;
		}
		snprintf(name, sizeof(name), "redirect, sentry s=%u", spins[s]);
		snprintf(extra, sizeof(extra), "(stub slept %.0f%%)",
		    100.0 * sl / ((double)n * r));
		report(name, v, r, extra);
	}
	return (0);
}
