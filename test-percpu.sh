#!/bin/sh

CC=gcc
CFLAGS="-pthread -Wall -O2"

RUNLIST="percpu-getcpu-nolock
percpu-nolock
percpu-lock-cmpxchg
percpu-cmpxchg
percpu-load-store"

NR_THREADS=${1}

${CC} ${CFLAGS} -DCONFIG_GETCPU_NOLOCK -o percpu-getcpu-nolock percpu.c
${CC} ${CFLAGS} -DCONFIG_NOLOCK -o percpu-nolock percpu.c
${CC} ${CFLAGS} -DCONFIG_LOCK_CMPXCHG -o percpu-lock-cmpxchg percpu.c
${CC} ${CFLAGS} -DCONFIG_CMPXCHG -o percpu-cmpxchg percpu.c
${CC} ${CFLAGS} -DCONFIG_LOAD_STORE -o percpu-load-store percpu.c

for a in ${RUNLIST}; do
	echo "Running ./${a} ${NR_THREADS} 10 0"
	./${a} ${NR_THREADS} 10 0
done
