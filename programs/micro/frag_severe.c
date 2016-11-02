#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <err.h>
#include <fcntl.h>

#define CHUNK (24 << 20)
typedef unsigned int uint32_t;

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s allocsize\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

void usr_handler(int signal) 
{
	printf("catch signal\n");
	exit(-1);
}

uint32_t size_tbl[] = {
	4 << 10,
	8 << 10,
	16 << 10,
	32 << 10,
	64 << 10,
	128 << 10,
	256 << 10,
	512 << 10,
	1024 << 10
	};

static uint32_t random_range(uint32_t a,uint32_t b) {
    uint32_t v;
    uint32_t range;
    uint32_t upper;
    uint32_t lower;
    uint32_t mask;

    if(a == b) {
        return a;
    }

    if(a > b) {
        upper = a;
        lower = b;
    } else {
        upper = b;
        lower = a; 
    }

    range = upper - lower;

    mask = 0;
    //XXX calculate range with log and mask? nah, too lazy :).
    while(1) {
        if(mask >= range) {
            break;
        }
        mask = (mask << 1) | 1;
    }


    while(1) {
        v = rand() & mask;
        if(v <= range) {
            return lower + v;
        }
    }
}

int main(int argc, char *argv[])
{
	long long kbtotal = 0;
	int i, j, numchunk, compaction = 0, use_huge = 1;
	int fd;
	unsigned int free_size;
	void **data;
	sigset_t set;
	struct sigaction sa;

	printf("%s\n", argv[1]);

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
	
	if (argc < 2 || kbtotal == 0)
		usage(argv[0], stderr);

	if (argc >= 3)
		use_huge = atoi(argv[2]);

	if (argc >= 4)
		compaction = atoi(argv[3]);

	if (use_huge)
		printf("Use huge page\n");
	else
		printf("Do not use huge page\n");

	if (compaction)
		printf("do compaction\n");
	else
		printf("Do not compact memory\n");

	numchunk = kbtotal / CHUNK;
	printf("allocate %llx memory,  numchunk = %d\n", kbtotal, numchunk);
	data = mmap(0, sizeof(void *) * numchunk, 
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	sa.sa_flags = 0;
	sa.sa_handler = usr_handler;

	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		errx(1, "sigaction");

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);

retry:
	printf("allocate memory\n");
	for (i = 0 ; i < numchunk; i++) {
		data[i] = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		if (!data[i]) {
			perror("alloc\n");
		}

		if (use_huge) {
			if (madvise(data[i], CHUNK, MADV_HUGEPAGE) < 0) {
				perror("error");
				exit(-1);
			}
		} else {
			if (madvise(data[i], CHUNK, MADV_NOHUGEPAGE) < 0) {
				perror("error");
				exit(-1);
			}
		}

		memset(data[i], 1, CHUNK);

		//for (j = 2, offset = 0; offset < CHUNK; j++) {
		for (j = 0; j < CHUNK; j+=(1<<20)) {
			free_size = size_tbl[random_range(0, 8)];
			//printf("%x, %lx\n", j, free_size);
			//munmap(data[i] + j, free_size);
			madvise(data[i] + j, free_size, MADV_DONTNEED);
		}
	}
	
	//printf("pausing\n");
	//pause();
	//sigwaitinfo(&set, NULL);
	
	usleep(100000);
	if (compaction) {
		printf("compaction\n");
		fd = open("/proc/sys/vm/compact_memory", O_WRONLY);
		if (fd < 0)
			errx(1, "cannot open file");

		if (write(fd, "1", 2) < 0)
			errx(1, "cannot write file");

		close(fd);
	}
	sleep(5);

	printf("retry\n");
	for (i = 0 ; i < numchunk; i++) 
		munmap(data[i], CHUNK);

	goto retry;
}
