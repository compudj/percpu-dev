all:
	./test-percpu.sh

.PHONY: clean

clean:
	rm -f percpu-getcpu-nolock percpu-nolock percpu-lock-cmpxchg percpu-cmpxchg percpu-load-store
