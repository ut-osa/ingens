#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

int huge_align = 0;
int debug = 1;
#define ALLOC_SIZE (2 << 20)
#define TOTAL_SIZE (1 << 30)
#define debug_printf(fmt, ...) \
	    do { if(debug) printf("DEBUG: " #fmt "\n",## __VA_ARGS__); } while(0)

#define ALIGN(x, boundary) (((x) + (boundary - 1)) & ~(boundary - 1))
int main(void)
{
	int i,j;
	void **data;
	long iter;

	iter = TOTAL_SIZE / ALLOC_SIZE;
	printf("%ld\n", iter);

	//data = (void **)malloc(sizeof(void *) * iter);
	data = mmap(0, sizeof(void *) * iter, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	for( i = 0; i < iter ; i++) {
		unsigned long addr;
		int diff;
		data[i] = mmap(0, ALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|0x100000, -1, 0);
		//madvise(data[i], ALLOC_SIZE, MADV_HUGEPAGE);

		if (huge_align) {
			addr = (unsigned long)data[i];
			diff = (ALIGN(addr, (2 << 20)) - addr);

			if (diff > 0) {
				munmap(data[i], diff);
retry:
				/* let's do not MREMAP_MAYMOVE */
				data[i] = mremap(data[i] + diff, (2 << 20) - diff, (2<<20), MREMAP_MAYMOVE);
				if ((long)data[i] < 0) {
					printf("remap failed -  %d : %s\n",errno, strerror(errno));
					exit(-1);
				}
			}
		}

		debug_printf("%p\n", data[i]);
		memset(data[i], 1, ALLOC_SIZE);
	}

	pause();
}
