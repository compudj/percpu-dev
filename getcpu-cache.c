/*
 * getcpu_cache.c
 *
 * Get CPU number cache
 *
 * Copyright (c) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE

#include <error.h>
#include <signal.h>
#include <stdio.h>
#include <ucontext.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <inttypes.h>
#include <urcu/system.h>
#include <urcu/compiler.h>
#include <urcu/uatomic.h>

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifdef __linux__
#include <syscall.h>
#endif

#if defined(_syscall0)
_syscall0(pid_t, gettid)
#elif defined(__NR_gettid)
#include <unistd.h>
static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t gettid(void)
{
	return getpid();
}
#endif

#if (CAA_BITS_PER_LONG == 32)
#define _ASM_PTR	" .long "
#else
#define _ASM_PTR	" .quad "
#endif

#define NR_CPU_INFO_MAX		4096
#define MMAP_LEN		\
		(NR_CPU_INFO_MAX * sizeof(struct cpu_info))

/* compile with -DCONFIG_* to select configuration. */

struct test_thread_info {
	uint64_t thread_loops;
};

static struct test_thread_info *test_thread_info;

static int nr_cpus;

static volatile int test_go, test_stop;

static unsigned int delay_loop;

static __thread int32_t curcpu_cache;

#define __NR_thread_local_abi	323
#define SYS_thread_local_abi	__NR_thread_local_abi

static inline int thread_local_abi(int32_t *tlap, size_t len, int flags)
{
	return syscall(SYS_thread_local_abi, tlap, len, flags);
}

static int get_nr_cpus(void)
{
	long ret;

	ret = sysconf(_SC_NPROCESSORS_ONLN);
	if (ret < 0) {
		perror("sysconf");
		return -1;
	}
	return (int) ret;
}

static void set_affinity(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask)) {
		perror("sched_setaffinity");
		abort();
	}
}

static void signal_off_save(sigset_t *oldset)
{
	sigset_t set;
	int ret;

	sigfillset(&set);
	ret = pthread_sigmask(SIG_BLOCK, &set, oldset);
	if (ret)
		abort();
}

static void signal_restore(sigset_t oldset)
{
	int ret;

	ret = pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	if (ret)
		abort();
}

#define sigsafe_fprintf(...)			\
	({					\
		sigset_t __set;			\
		int __ret;			\
						\
		signal_off_save(&__set);	\
		__ret = fprintf(__VA_ARGS__);	\
		signal_restore(__set);		\
		__ret;				\
	})

#define sigsafe_fprintf_dbg(...)

static int init_thread_getcpu_cache(void)
{
	ssize_t ret;

	ret = thread_local_abi(&curcpu_cache, sizeof(curcpu_cache), 0);
	if (ret < 0) {
		perror("getcpu_cache");
		return -1;
	} else if (ret < sizeof(curcpu_cache)) {
		fprintf(stderr, "thread_local_abi returned %zd\n",
			ret);
		return -1;
	}
	return 0;
}

static void fini_thread_percpu(void)
{
}

static
void do_delay_loop(int nr)
{
	int i;

	for (i = 0; i < nr; i++)
		caa_cpu_relax();
}

static void *thread_fct(void *arg)
{
	int ret;
	int thread_nr = (long) arg;
	int cpu = thread_nr % nr_cpus;
	int last_cpu, cur_cpu;
	uint64_t loop_count = 0,
		diff_count = 0,
		migrate_count = 0;

	set_affinity(cpu);

	sigsafe_fprintf(stderr, "[tid: %d, cpu: %d] Thread starts\n",
		gettid(), cpu);
	ret = init_thread_getcpu_cache();
	if (ret) {
		abort();
	}

	while (!test_go) {
	}
	cmm_smp_mb();

	last_cpu = CMM_LOAD_SHARED(curcpu_cache);
	for (;;) {
		cur_cpu = CMM_LOAD_SHARED(curcpu_cache);
		if (cur_cpu != sched_getcpu())
			diff_count++;
		loop_count++;
		if (cur_cpu != last_cpu)
			migrate_count++;
		if (!(loop_count & 0xfffffff))
			sigsafe_fprintf(stderr, "[tid: %d] Thread status: %" PRIu64 " diff. CPUs cache vs sched_getcpu(), %" PRIu64 " migrations.\n",
				gettid(), diff_count, migrate_count);
		last_cpu = cur_cpu;
		do_delay_loop(delay_loop);
		if (caa_unlikely(test_stop)) {
			break;
		}
	}
	fini_thread_percpu();
	test_thread_info[thread_nr].thread_loops = loop_count;
	sigsafe_fprintf(stderr, "[tid: %d] Thread end: %" PRIu64 " diff. CPUs cache vs sched_getcpu(), %" PRIu64 " migrations.\n",
		gettid(), diff_count, migrate_count);

	return NULL;
}

int main(int argc, char **argv)
{
	int ret = 0, i, retval = -1, err;
	pthread_t *tids;
	void *tret;
	uint64_t tot_loops = 0;
	unsigned int remain, duration;
	int nr_threads;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s [nr_threads] [seconds] [delay_loop]\n",
			argv[0]);
		goto end;
	}
	nr_threads = atoi(argv[1]);
	if (nr_threads < 0) {
		fprintf(stderr, "Use integer >= 0 for nr_threads\n");
		goto end;
	}
	duration = atoi(argv[2]);
	if (duration < 0) {
		fprintf(stderr, "Use positive integer for seconds\n");
		goto end;
	}
	delay_loop = atoi(argv[3]);
	if (delay_loop < 0) {
		fprintf(stderr, "Use positive integer for delay_loop\n");
		goto end;
	}
	nr_cpus = get_nr_cpus();
	if (nr_cpus <= 0) {
		fprintf(stderr, "Error getting the number of CPUs\n");
		goto end;
	}

	test_thread_info = calloc(nr_threads, sizeof(*test_thread_info));
	if (!test_thread_info)
		goto end_fini_percpu;
	tids = calloc(nr_threads, sizeof(*tids));
	if (!tids)
		goto end_free_test_thread_info;

	for (i = 0; i < nr_threads; i++) {
		err = pthread_create(&tids[i], NULL, thread_fct,
			(void *) (long) i);
		if (err != 0)
			goto end_free_tids;
	}

	cmm_smp_mb();

	test_go = 1;

	remain = duration;
	do {
		remain = sleep(remain);
	} while (remain > 0);

	test_stop = 1;

	for (i = 0; i < nr_threads; i++) {
		err = pthread_join(tids[i], &tret);
		if (err != 0)
			goto end_free_tids;
		tot_loops += test_thread_info[i].thread_loops;
	}

	fprintf(stderr, "SUMMARY: %u threads, %u cores, %u delay loops, %" PRIu64 " loops, %d s  (%4g ns/[loops/core])\n",
		nr_threads, nr_cpus, delay_loop,
		tot_loops, duration,
		(double) duration * min(nr_cpus, nr_threads) * 1000000000ULL/ (double) tot_loops);

	retval = 0;

end_free_tids:
	free(tids);
end_free_test_thread_info:
	free(test_thread_info);
end_fini_percpu:
	if (ret) {
		retval = -1;
		fprintf(stderr, "Error in fini_percpu\n");
	}
end:
	if (!retval)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}
