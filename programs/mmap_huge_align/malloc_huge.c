#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#define ALLOC_SIZE (2 << 20)
//#define ALLOC_SIZE (1 << 30)
#define TOTAL_SIZE (1 << 30)
#define debug_printf(fmt, ...) \
	    do { if(debug) printf("DEBUG: " #fmt "\n",## __VA_ARGS__); } while(0)

#define ALIGN(x, boundary) (((x) + (boundary - 1)) & ~(boundary - 1))
int main(void)
{
	int i, num_chunk = 10;
	void **buf;

	buf = (void *)malloc(sizeof(void *) * num_chunk);

	printf("-------------------------\n");
	for (i = 0 ; i < num_chunk; i++) {
		buf = malloc(ALLOC_SIZE);
		memset(buf, i, ALLOC_SIZE);

		printf("%p\n", buf);
		printf("%d\n", ((int *)buf)[20]);
		printf("-------------------------\n");
	}

	pause();
}
