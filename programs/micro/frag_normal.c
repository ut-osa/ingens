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

#define CHUNK (4 * 1024 * 1024)

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s allocsize <compaction:0 or 1>\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

void usr_handler(int signal) 
{
	printf("catch signal\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	long long kbtotal = 0;
	int i, j, numchunk, compaction = 0, iteration = 0;
	int fd;
	unsigned int offset;
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

	if (argc >= 3) {
		compaction = atoi(argv[2]);
	}

	numchunk = kbtotal / CHUNK;
	printf("allocate %llx memory,  numchunk = %d\n", kbtotal, numchunk);
	data = mmap(0, sizeof(void *) * numchunk, 
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS | 0x100000, -1, 0);

	if (madvise(data, sizeof(void *) * numchunk, MADV_HUGEPAGE) < 0) {
		perror("error");
		exit(-1);
	}

	sa.sa_flags = 0;
	sa.sa_handler = usr_handler;

	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		errx(1, "sigaction");

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);

retry:
	iteration++;
	for (i = 0 ; i < numchunk; i++) {
        // 0x100000 is hugepage aligned mmap
        // Only possible for linux-4.3-osa kernel
		data[i] = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE | 0x100000, -1, 0);

		if (!data[i]) {
			perror("alloc\n");
		}

		if (madvise(data[i], CHUNK, MADV_HUGEPAGE) < 0) {
			perror("error");
			exit(-1);
		}

		memset(data[i], 1, CHUNK);
		//usleep(1000);

		for (j = 2, offset = 0; j < 20; j++) {
			madvise(data[i] + offset, (CHUNK / (1<<j)), MADV_DONTNEED);
			offset += (CHUNK / (1<<(j-1)));
		}
	}
	
	
	printf("%d: fragmentation is done!\n", iteration);
	fflush(stdout);

	//pause();

	sleep(1);
	if ((iteration % 4 == 0) && compaction) {
        // This requires sudo permission
		printf("compaction\n");
		fflush(stdout);
		fd = open("/proc/sys/vm/compact_memory", O_WRONLY);
		if (fd < 0)
			errx(1, "cannot open file");

		if (write(fd, "1", 2) < 0)
			errx(1, "cannot write file");

		close(fd);
	}

	for (i = 0 ; i < numchunk; i++) 
		munmap(data[i], CHUNK);

	printf("retry\n");
	goto retry;
}
