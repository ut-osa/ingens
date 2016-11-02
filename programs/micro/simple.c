#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define SIZE (1024 << 20) 
#define NR  SIZE / sizeof(char) 

void main(void)
{
	char *buf;
	unsigned long i;
	int iter, bias;

	buf = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, 
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (!buf) {
		perror("alloc\n");
	}

	if (madvise(buf, SIZE, MADV_HUGEPAGE) < 0) {
		perror("error");
		exit(-1);
	}

	if (madvise(buf, SIZE, MADV_MERGEABLE ) < 0) {
		perror("error");
		exit(-1);
	}

	iter = bias = 0;
verify:
	if ((iter % 8) == 0) {
		bias = (iter % 7);
		printf("change bias %d\n", bias);

		for (i=0; i < NR; i++)
			buf[i] = (i % 5) + bias;
	}

	for (i=0; i < NR; i++) {
		if (buf[i] != ((i % 5) + bias)) {
			fprintf(stderr, "verifying failed %lu %d\n", i, buf[i]);
			exit(-1);
		}
	}

	usleep(10000);
	printf("verify OK\n");

	iter++;
	goto verify;

	return;
}
