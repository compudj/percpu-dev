all:
	gcc -Wall -O2 -pthread -o getcpu-cache getcpu-cache.c
	./test-percpu.sh

.PHONY: clean

clean:
	rm -f percpu-getcpu-nolock percpu-nolock percpu-lock-cmpxchg percpu-cmpxchg percpu-load-store
