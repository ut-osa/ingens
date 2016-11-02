/* This application is designed to guage memory pressure and
 * same page sharing.
 * 
 * The University of Texas at Austin
 * Youngjin Kwon 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>

#define CHUNK (4 * 1024 * 1024)

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s <allocsize> <use_huge:0 or 1>" 
			"<sleep_between_alloc:us>\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

int main(int argc, char *argv[])
{
	long long kbtotal = 0, kballoc;
	unsigned int i, j, k, numchunk, alloc, bias = 0;
	unsigned long iter;
	char **mem, *tmp;
	int use_huge = 0, sleep_intval = 0;
	struct timeval t_start, t_end, t_elap;

	if (argc < 2) {
		usage(argv[1], stderr);
		exit(-1);
	}

	if (argc >= 2) {
		char *end = NULL;
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

	if (kbtotal == 0)
		usage(argv[0], stderr);

	if (argc >= 3) {
		use_huge = atoi(argv[2]);
		printf("use hugepage \n");
	}

	if (argc >= 4) {
		sleep_intval = atoi(argv[3]);
		printf("sleep intval between allocation %dus\n", 
				sleep_intval);
	}

	numchunk = (kbtotal + CHUNK - 1) / CHUNK;
	mem = calloc(numchunk, sizeof(*mem));

	printf("number of chunk %d, total size %lld\n", numchunk, kbtotal);
	if (mem == NULL) {
		fprintf(stderr, "error allocating initial chunk array\n");
		exit(-1);
	}

	alloc = CHUNK;
	printf("[%d] allocating %lld kbytes in 0x%x kbyte chunks\n",
			getpid(), kbtotal, alloc);
	for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		//while (alloc > 0 && (mem[i] = malloc(alloc * 1024)) == NULL) {
		while (alloc > 0 && (mem[i] = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
						MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == NULL) {
			fprintf(stderr, "malloc(%u) failed (%lld/%lld)\n",
					alloc, kballoc, kbtotal);
			alloc /= 2;
		}
		if (alloc == 0)
			break;

		if (use_huge && madvise(mem[i], alloc, MADV_HUGEPAGE) < 0) {
			perror("error");
			exit(-1);
		}

		if (madvise(mem[i], alloc, MADV_MERGEABLE) < 0) {
			perror("error");
			exit(-1);
		}

		if ((i % 10) == 0)
			printf("touching %p ([%lld-%lld]/%lld)\n", mem[i], kballoc,
					kballoc + alloc - 1, kbtotal);
		tmp = mem[i];
		for (j = 0; j < 4095; j++, tmp++)
			*tmp = 8;

		for (k = 0; k < alloc - j; k++, tmp++)
			*tmp = (i % 3) + 8;

		if (sleep_intval)
			usleep(sleep_intval);

	}
	if (kballoc == 0)
		exit(-2);

	kbtotal = kballoc;
	printf("touched %lld kbytes\n", kballoc);

	iter = 0;
verify:
	/* for testing, ksmd hugepage sharing 
	 * intentionally, break shared mapping */
#if 0
	if ((iter % 5) == 2) {
		alloc = CHUNK;
		printf("Disable KSM merging\n");
		for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
			if (kbtotal - kballoc < alloc)
				alloc = kbtotal - kballoc;
			tmp = mem[i];

			if (madvise(mem[i], alloc, MADV_UNMERGEABLE) < 0) {
				perror("error");
				exit(-1);
			}
		}
	}

	if ((iter % 5) == 3) {
		alloc = CHUNK;
		printf("Enable KSM merging\n");
		for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
			if (kbtotal - kballoc < alloc)
				alloc = kbtotal - kballoc;
			tmp = mem[i];

			if (madvise(mem[i], alloc, MADV_MERGEABLE) < 0) {
				perror("error");
				exit(-1);
			}
		}
	}
#endif

	alloc = CHUNK;
	/* Usually, changing bias value is faster than verificaiton
	 * since it only uses memset (possibly vector operation).
	 * Therefore, changing bias shows relatively bursty pattern
	 * of memory access than what verfication does */
	if ((iter % 2) == 0) {
		bias = (iter % 3);
		printf("[%lu] CHANGE BIAS VALUE %u\n", iter, bias);
		for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
			if (kbtotal - kballoc < alloc)
				alloc = kbtotal - kballoc;
			tmp = mem[i];

			/*
			if ((iter % 5) == 2) {
				printf("Disable KSM merging\n");
				if (madvise(mem[i], alloc, MADV_UNMERGEABLE) < 0) {
					perror("error");
					exit(-1);
				}
			} else if ((iter % 5) == 3) {
				printf("Enable KSM merging\n");
				if (madvise(mem[i], alloc, MADV_MERGEABLE) < 0) {
					perror("error");
					exit(-1);
				}
			}
			*/
			memset(tmp, bias + 2, 4096);

			memset(tmp + 4096, bias + 3, alloc - 4096);

			//if (i % 2 == 0)
			if (sleep_intval)
				usleep(sleep_intval);

		}
		printf("  values: leading block %x, trailing block %x\n",
				bias + 2, bias + 3);
	}

	alloc = CHUNK;
	printf("verifying 0x%llx kbytes in %x kbyte chunks\n", kbtotal, alloc);
	gettimeofday(&t_start, NULL);
	for (i = kballoc = 0; i < numchunk; i++, kballoc += alloc) {
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		tmp = mem[i];

		/* printf causes slowdown of progress.
		if ((i % 20) == 0)
			printf("verifying %p (%lld/%lld)\n", tmp, kballoc, kbtotal);
		*/

		for (j = 0; j < 4096; j++, tmp++) {
			if (*tmp != (bias + 2)) {
				printf("[leading block] verifing error at %p offset 0x%x: val %x\n", 
						tmp, j, *tmp);
				exit(-1);
			}
		}
		for (k = 0; k < alloc - j; k++, tmp++) {
			if (*tmp != (bias + 3)) {
				printf("[trailing block] verifing error at %p offset 0x%x: val %x truth %x\n", 
						tmp, k + 4096, *tmp,  bias + 3);
				exit(-1);
			}
		}

		if (sleep_intval)
			usleep(sleep_intval);
	}
	gettimeofday(&t_end, NULL);

	timersub(&t_end, &t_start, &t_elap);

	printf("verified %lld kbytes\n", kballoc);
	fprintf(stderr, "%lu.%06lu\n", t_elap.tv_sec, t_elap.tv_usec);

	//pause();
	iter++;
	goto verify;
	return 0;
}
