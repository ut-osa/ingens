#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <assert.h>

char *data;

int randint(int n) {
	if ((n - 1) == RAND_MAX) {
		return rand();
	} else {
		// Chop off all of the values that would cause skew...
		long end = RAND_MAX / n; // truncate skew
		assert (end > 0L);
		end *= n;

		// ... and ignore results from rand() that fall above that limit.
		// (Worst case the loop condition should succeed 50% of the time,
		// so we can expect to bail out of this loop pretty quickly.)
		int r;
		while ((r = rand()) >= end);

		return r % n;
	}
}

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s <allocsize>\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

int main(int argc, char *argv[])
{
	unsigned long kbtotal = 0, pgtotal = 0, i, idx, offset;
	char c = 0;
	unsigned int ratio;

	if (argc >= 2) {
		char *end = NULL;
		/* BOF??? */
		kbtotal = strtoull(argv[1], &end, 0);

		switch(*end) {
			case 'g':
			case 'G':
				kbtotal *= 1024;
			case 'm':
			case 'M':
				kbtotal *= 1024;
			case '\0':
			case 'k':
			case 'K':
				kbtotal *= 1024;
				break;
			case 'p':
			case 'P':
				kbtotal *= 4;
				break;
			default:
				usage(argv[0], stderr);
				break;
		}
	}

	if (argc >= 3)
		ratio = atoi(argv[2]);
	else
		ratio = 50;

	printf("size 0x%lx KB, ratio %d \n", kbtotal, ratio);

	pgtotal = kbtotal >> 12;

	data = (char *)mmap(NULL, kbtotal, PROT_READ|PROT_WRITE, 
			MAP_PRIVATE|MAP_ANONYMOUS| 0x100000, -1, 0);

	if (data == MAP_FAILED) {
		printf("mmap failed\n");
		exit(-1);
	}


	for ( i = 0; i < (pgtotal * ratio) / 100 ; i++) {
		c = randint(128);
		idx = randint(pgtotal);
		offset = randint(4096);

		if (idx * 4096 + offset > kbtotal) {
			printf("%ld %ld\n", idx * 4096 + offset, offset);
			exit(-1);
		}
		data[idx * 4096 + offset] = c;
	}

	printf("done\n");
	pause();
	return 0;
}
