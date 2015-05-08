/*
 * percpu.c
 *
 * Per-CPU Critical Sections
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

/* TODO: nesting keeping cpuid, chain sighandlers. */

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

//#define NR_THREADS	64
//#define NR_THREADS	16
#define NR_THREADS	8
//#define NR_THREADS	4
//#define NR_THREADS	1
/* For testing with multiple threads per cpu */
//#define NR_CPUS		64
//#define NR_CPUS		32
//#define NR_CPUS		8
#define NR_CPUS		8

#define NR_CPU_INFO_MAX		4096
#define MMAP_LEN		\
		(NR_CPU_INFO_MAX * sizeof(struct cpu_info))

/* compile with -DCONFIG_* to select configuration. */

#ifdef CONFIG_LOCK_CMPXCHG

static const char *config_name = "lock; cmpxchg";
# define USE_UNLOCK
# define USE_GETCPU

#elif defined(CONFIG_CMPXCHG)

static const char *config_name = "cmpxchg";
# define USE_SIGNALS
# define USE_UNLOCK
# define USE_GETCPU

#elif defined(CONFIG_LOAD_STORE)

static const char *config_name = "loads+store";
# define USE_SIGNALS
# define USE_UNLOCK
# define USE_GETCPU

#elif defined(CONFIG_GETCPU_NOLOCK)

static const char *config_name = "getcpu + no locking";
# define USE_GETCPU

#else	/* no locking */

static const char *config_name = "no getcpu + no locking";

#endif

struct percpu_fault {
	void *begin;
	void *end;
	void *restart;
};

extern struct percpu_fault const __start___percpu_lock_fault[]
	__attribute((weak));
extern struct percpu_fault const __stop___percpu_lock_fault[]
	__attribute((weak));

static int filefd;

static volatile int test_go, test_stop;

static unsigned int delay_loop;

struct cpu_info {
	int lock;
	int data;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

struct thread_percpu_user {
	/* Kernel ABI. */
	int32_t nesting;
	int32_t signal_sent;
	int32_t signo;
	int32_t current_cpu;

	/* Userland only. */
	struct cpu_info *mmap_range;
	int8_t protected;
	int8_t faulted;

	long thread_nr;	/* testing */
};

#define __NR_percpu	323
#define SYS_percpu	__NR_percpu

static inline int percpu(struct thread_percpu_user *tpu)
{
	return syscall(SYS_percpu, tpu);
}

static __thread struct thread_percpu_user tpu;

static uint64_t thread_loops[NR_THREADS];
static uint64_t nr_preempt_sig[NR_THREADS];

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

static struct cpu_info *map_range(void)
{
	struct cpu_info *mmap_range;

	mmap_range = mmap(NULL, MMAP_LEN, PROT_READ | PROT_WRITE,
			MAP_SHARED, filefd, 0);
	if (mmap_range == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	return mmap_range;
}

static void unmap_range(struct cpu_info *mmap_range)
{
	int ret;

	ret = munmap(mmap_range, MMAP_LEN);
	if (ret) {
		perror("munmap");
		abort();
	}
}

static void unprotect_range(void)
{
	int ret;

	ret = mprotect(tpu.mmap_range,
		MMAP_LEN, PROT_READ | PROT_WRITE);
	if (ret) {
		perror("mprotect");
		abort();
	}
	CMM_STORE_SHARED(tpu.protected, 0);
}

static int init_thread_percpu(void)
{
	int ret;

	tpu.mmap_range = map_range();
	ret = mlock(&tpu, sizeof(tpu));
	if (ret) {
		perror("mlock");
		return -1;
	}
	tpu.signo = SIGUSR1;
	ret = percpu(&tpu);
	if (ret) {
		perror("percpu");
		return -1;
	}
	return 0;
}

static void fini_thread_percpu(void)
{
	int ret;

	ret = munlock(&tpu, sizeof(tpu));
	if (ret) {
		perror("munlock");
	}
	unmap_range(tpu.mmap_range);
	tpu.mmap_range = NULL;
}

/*
 * Globally atomic lock with lock prefix.
 */
static inline void inline_lock_global(int *lock)
{
	asm volatile (
	"1:\n\t"
	"xorl %%eax, %%eax\n\t"
	"lock; cmpxchgl %1, %0\n\t"
	"jnz 1b\n\t"
	"2:\n\t"
	".pushsection __percpu_lock_fault, \"a\"\n\t"
	_ASM_PTR "1b, 2b, 2b\n\t"
	".popsection\n\t"
		: "+m" (*__hp(lock))
		: "r" (1)
		: "memory", "cc", "eax");
}

/*
 * Lock atomic on a per-cpu basis (no lock prefix, but atomic instruction.)
 * OK to use if migration is disabled.
 */
static inline void inline_lock_migrate_off(int *lock)
{
	asm volatile (
	"1:\n\t"
	"xorl %%eax, %%eax\n\t"
	"cmpxchgl %1, %0\n\t"
	"jnz 1b\n\t"
	"2:\n\t"
	".pushsection __percpu_lock_fault, \"a\"\n\t"
	_ASM_PTR "1b, 2b, 2b\n\t"
	".popsection\n\t"
		: "+m" (*__hp(lock))
		: "r" (1)
		: "memory", "cc", "eax");
}

/*
 * Lock not atomic even on a per-cpu basis (no lock prefix, sequence of
 * instructions). OK to use if preemption is disabled.
 */
static inline void inline_lock_preempt_off(int *lock)
{
	asm volatile (
	"1:\n\t"
	"movzx %0, %%eax\n\t"
	"testl %%eax, %%eax\n\t"
	"jne 1b\n\t"
	"movl $1, %0\n\t"
	"2:\n\t"
	".pushsection __percpu_lock_fault, \"a\"\n\t"
	_ASM_PTR "1b, 2b, 2b\n\t"
	".popsection\n\t"
		: "+m" (*__hp(lock))
		:
		: "memory", "cc", "eax");
}

//static inline void inline_lock(int *lock)
static inline void inline_lock(int *lock)
{
#ifdef CONFIG_LOCK_CMPXCHG
	inline_lock_global(lock);
#endif
#ifdef CONFIG_CMPXCHG
	inline_lock_migrate_off(lock);
#endif
#ifdef CONFIG_LOAD_STORE
	inline_lock_preempt_off(lock);
#endif
}

static inline void inline_unlock(int *lock)
{
#ifdef USE_UNLOCK
	/* Not needed for x86-TSO: cmm_smp_mb(); */
	uatomic_set(lock, 0);
#endif
}

static int handle_percpu_begin_fault(void)
{
	int restart = 0;

	CMM_STORE_SHARED(tpu.signal_sent, 0);
	if (CMM_LOAD_SHARED(tpu.protected)) {
		unprotect_range();
		if (CMM_LOAD_SHARED(tpu.faulted)) {
			CMM_STORE_SHARED(tpu.faulted, 0);
			restart = 1;
		}
	}
	return restart;
}

static inline
int percpu_begin(void)
{
	int current_cpu;

restart:
#ifdef USE_SIGNALS
	tpu.nesting++;
	cmm_barrier();
#endif
	//current_cpu = sched_getcpu();
	current_cpu = CMM_LOAD_SHARED(tpu.current_cpu);
	inline_lock(&tpu.mmap_range[current_cpu].lock);
	cmm_barrier();
#ifdef USE_SIGNALS
	tpu.nesting--;
	cmm_barrier();
#endif

	if (caa_unlikely(CMM_LOAD_SHARED(tpu.signal_sent))) {
		if (handle_percpu_begin_fault())
			goto restart;
	}
	return current_cpu;
}

static inline
void percpu_end(int current_cpu)
{
	inline_unlock(&tpu.mmap_range[current_cpu].lock);
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
	int cpu = thread_nr % NR_CPUS;
	uint64_t loop_count = 0;

	tpu.thread_nr = thread_nr;

	set_affinity(cpu);

	sigsafe_fprintf(stderr, "[tid: %d, cpu: %d] Thread starts\n",
		gettid(), cpu);
	ret = init_thread_percpu();
	if (ret) {
		abort();
	}

	while (!test_go) {
	}
	cmm_smp_mb();

	for (;;) {
		int current_cpu;

#ifdef USE_GETCPU
		current_cpu = percpu_begin();
#else
		current_cpu = cpu;
#endif
		if (CMM_LOAD_SHARED(tpu.mmap_range[current_cpu].data) != 0) {
			sigsafe_fprintf(stderr, "Corrupted value\n");
			abort();
		}
		CMM_STORE_SHARED(tpu.mmap_range[current_cpu].data, 1);
		CMM_STORE_SHARED(tpu.mmap_range[current_cpu].data, 0);
#ifdef USE_GETCPU
		percpu_end(current_cpu);
#endif
		do_delay_loop(delay_loop);
		loop_count++;
		if (caa_unlikely(test_stop)) {
			break;
		}
	}
	fini_thread_percpu();
	thread_loops[thread_nr] = loop_count;
	return NULL;
}

static void print_regs(ucontext_t *ctx)
{
	mcontext_t *mctx = &ctx->uc_mcontext;
	int i;

	for (i = 0; i < NGREG; i++) {
		sigsafe_fprintf_dbg(stderr, "greg[%d]: %p\n",
			i, (void *) mctx->gregs[i]);
	}
}

static void *get_fault_restart_address(void *addr)
{
	const struct percpu_fault *iter;

	for (iter = __start___percpu_lock_fault;
			iter < __stop___percpu_lock_fault;
			iter++) {
		if (addr >= iter->begin && addr < iter->end) {
			return iter->restart;
		}
	}
	return NULL;
}

static void sighandler(int sig, siginfo_t *siginfo, void *data)
{
	ucontext_t *ctx = data;
	int ret;

	sigsafe_fprintf_dbg(stderr, "SIG: %d\n", sig);

	switch (sig) {
	case SIGSEGV:
		sigsafe_fprintf_dbg(stderr, "[tid: %d] SIGSEGV caught at address %p\n",
			gettid(), siginfo->si_addr);
		print_regs(ctx);
		if (tpu.mmap_range &&
				(struct cpu_info *) siginfo->si_addr
					>= tpu.mmap_range
				&& (struct cpu_info *) siginfo->si_addr
					< tpu.mmap_range + NR_CPU_INFO_MAX) {
			sigsafe_fprintf_dbg(stderr, "Skipping faulty access\n");
			ctx->uc_mcontext.gregs[REG_RIP] =
				(long) get_fault_restart_address((void *) ctx->uc_mcontext.gregs[REG_RIP]);
			CMM_STORE_SHARED(tpu.faulted, 1);
		} else {
			struct sigaction sa;
			sigset_t sigset;

			if ((ret = sigemptyset(&sigset)) < 0) {
				perror("sigemptyset");
				abort();
			}
			sa.sa_handler = SIG_DFL;
			sa.sa_mask = sigset;
			sa.sa_flags = 0;
			ret = sigaction(sig, &sa, NULL);
			if (ret) {
				perror("sigaction");
				abort();
			}
			ret = raise(sig);
			if (ret) {
				perror("raise");
				abort();
			}
		}
		break;
	case SIGUSR1:
	{
		sigsafe_fprintf_dbg(stderr, "[tid: %d] SIGUSR1 caught at instruction %p\n",
			gettid(), (void *) ctx->uc_mcontext.gregs[REG_RIP]);
		if (!tpu.mmap_range) {
			sigsafe_fprintf(stderr, "Signal received on thread unaware of percpu critical section. Dismissed.\n");
			break;
		}
		/* Protect memory range */
		if (CMM_LOAD_SHARED(tpu.nesting)) {
			sigsafe_fprintf_dbg(stderr, "Nested within C.S., protect pages.\n");
			ret = mprotect(tpu.mmap_range, MMAP_LEN, PROT_NONE);
			if (ret) {
				perror("mprotect");
				abort();
			}
			CMM_STORE_SHARED(tpu.protected, 1);
		}
		nr_preempt_sig[tpu.thread_nr]++;
		break;
	}
	default:
		break;
	}
}

static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		return ret;
	}

	sa.sa_sigaction = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = SA_SIGINFO;
	if ((ret = sigaction(SIGSEGV, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}
	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}
	sigsafe_fprintf(stderr, "[tid: %d] Signal handler set for SIGSEGV, SIGUSR1\n",
			gettid());

	return ret;
}

static int create_map(void)
{
	int ret;

	/* TODO: Use memfd starting from 3.17 */
	ret = unlink("/tmp/testmap");
	if (ret && errno != ENOENT) {
		perror("unlink");
		return -1;
	}
	filefd = open("/tmp/testmap", O_RDWR | O_CREAT, S_IRWXU);
	if (filefd < 0) {
		perror("open");
		return -1;
	}
	ret = unlink("/tmp/testmap");
	if (ret && errno != ENOENT) {
		perror("unlink");
		return -1;
	}
	return 0;
}

int init_percpu(void)
{
	int ret, i;
	struct cpu_info *mmap_range;

	ret = set_signal_handler();
	if (ret) {
		fprintf(stderr, "set_signal_handler error\n");
		goto error;
	}
	ret = create_map();
	if (ret) {
		fprintf(stderr, "create_map error\n");
		goto error;
	}
	ret = fallocate(filefd, 0, 0, MMAP_LEN);
	if (ret) {
		perror("fallocate");
		goto error;
	}
	mmap_range = map_range();
	if (!mmap_range) {
		fprintf(stderr, "map_range error\n");
		goto error;
	}
	for (i = 0; i < NR_CPU_INFO_MAX; i++) {
		mmap_range[i].lock = 0;
	}
	unmap_range(mmap_range);

	return 0;

error:
	return -1;
}

int fini_percpu(void)
{
	int ret;

	ret = close(filefd);
	if (ret) {
		perror("close");
		goto error;
	}
	return 0;

error:
	return -1;

}

int main(int argc, char **argv)
{
	int ret, i;
	int err;
	pthread_t tid[NR_THREADS];
	void *tret;
	uint64_t tot_loops = 0, tot_sig = 0;
	unsigned int remain, duration;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [seconds] [delay_loop]\n",
			argv[0]);
		goto error;
	}
	duration = atoi(argv[1]);
	if (duration < 0) {
		fprintf(stderr, "Use positive integer for seconds\n");
		goto error;
	}
	delay_loop = atoi(argv[2]);
	if (delay_loop < 0) {
		fprintf(stderr, "Use positive integer for delay_loop\n");
		goto error;
	}
	ret = init_percpu();
	if (ret) {
		fprintf(stderr, "init_percpu error\n");
		goto error;
	}

	for (i = 0; i < NR_THREADS; i++) {
		err = pthread_create(&tid[i], NULL, thread_fct,
			(void *) (long) i);
		if (err != 0)
			goto error;
	}

	cmm_smp_mb();

	test_go = 1;

	remain = duration;
	do {
		remain = sleep(remain);
	} while (remain > 0);

	test_stop = 1;

	for (i = 0; i < NR_THREADS; i++) {
		err = pthread_join(tid[i], &tret);
		if (err != 0)
			goto error;
		tot_loops += thread_loops[i];
		tot_sig += nr_preempt_sig[i];
	}

	fprintf(stderr, "SUMMARY: [%s] %u threads, %u cores, %u delay loops, %" PRIu64 " loops, %" PRIu64 " preempt signals / %d s  (%4g ns/[loops/core])\n",
		config_name, NR_THREADS, NR_CPUS, delay_loop,
		tot_loops, tot_sig, duration,
		(double) duration * min(NR_CPUS, NR_THREADS) * 1000000000ULL/ (double) tot_loops);

	ret = fini_percpu();
	if (ret) {
		goto error;
	}

	exit(EXIT_SUCCESS);

error:
	exit(EXIT_FAILURE);
}
