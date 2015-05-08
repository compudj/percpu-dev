all:
	gcc -O2 -o percpu -pthread percpu.c

.PHONY: clean

clean:
	rm -f percpu
