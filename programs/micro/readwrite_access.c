#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>

#define HPAGE_SIZE (1 << 21)

char *locality;

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
	unsigned long kbtotal = 0, pgtotal = 0, i, j, k, idx, offset;
	unsigned long locality_pg;
	char c = 0;
	char buf[4096];
	unsigned int iteration;
	struct timeval t_start, t_end, t_elap;

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
		iteration = atoi(argv[2]);
	else
		iteration = 50;

	printf("size 0x%lx KB, iteration %d \n", kbtotal, iteration);

	pgtotal = kbtotal / 4;

	locality = (char *)mmap(NULL, kbtotal, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|0x100000, -1, 0);

	if (locality == MAP_FAILED) {
		printf("mmap failed\n");
		exit(-1);
	}

	//memset(locality, 0, kbtotal);

	gettimeofday(&t_start, NULL);
	for ( i = 0; i < iteration; i++) {
		idx = randint((pgtotal >> 9));	
		for ( j = 0; j < HPAGE_SIZE ; j++) {
			if (idx % 100 == 0)
				locality[idx * HPAGE_SIZE + j] = j;
			else
				c = locality[idx * HPAGE_SIZE + j];

			c++;
		}
	}
	gettimeofday(&t_end, NULL);
	timersub(&t_end, &t_start, &t_elap);

	printf("%lu.%06lu\n", t_elap.tv_sec, t_elap.tv_usec);
	fflush(stdout);

	printf("done\n");
	pause();
	return 0;
}
