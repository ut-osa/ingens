#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>

#define CHUNK (2 * 1024 * 1024)
#define HEAD_BLOCK_SIZE_KB 4096
#define MAP_HPAGE       0x100000

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s <allocsize> <1,0:1-madv_huge, 0-basepage> <1,0:1-rand_access,0-seq_access>\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

int main(int argc, char *argv[])
{
	long long kbtotal = 0, kballoc;
	int i, j, k, numchunk, alloc, iter, bias = 0;
	char **mem, *tmp;
	struct timeval t_start, t_end, t_elap;
	int madv_huge = 1, rand_access = 0;

	if (argc < 2)
		usage(argv[0], stderr);

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

	if (argc >= 3) {
		madv_huge = atoi(argv[2]);
	}

	if (argc >= 4) {
		rand_access = atoi(argv[3]);
	}

	if (!madv_huge)
		printf("do not madvise for MADV_HUGEPAGE\n");

	srand(time(NULL));

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
						MAP_ANONYMOUS | MAP_PRIVATE | MAP_HPAGE, -1, 0)) == NULL) {
			fprintf(stderr, "malloc(%u) failed (%lld/%lld)\n",
					alloc, kballoc, kbtotal);
			alloc /= 2;
		}
		if (alloc == 0)
			break;

		if (madv_huge) {
			if (madvise(mem[i], alloc, MADV_HUGEPAGE) < 0) {
				perror("error");
				exit(-1);
			}
		}

		if (madvise(mem[i], alloc, MADV_MERGEABLE) < 0) {
			perror("error");
			exit(-1);
		}

		/*
		if ((i % 10) == 0)
			printf("touching %p ([%lld-%lld]/%lld)\n", mem[i], kballoc,
					kballoc + alloc - 1, kbtotal);
		*/

		tmp = mem[i];
		for (j = 0; j < alloc; j++, tmp++)
			*tmp = 1;
	}

	if (kballoc == 0)
		exit(-2);

	kbtotal = kballoc;
	printf("touched %lld kbytes\n", kballoc);

	iter = 0;

	if (rand_access) 
		goto rand_verify;
	else
		goto seq_verify;

	///////////////////////////////////////////////////////////////////////////
seq_verify:
	alloc = CHUNK;
	bias = (iter % 3);
	printf("[%d]CHANGE BIAS VALUE %d\n", iter, bias);
	for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		tmp = mem[i];
		for (j = 0; j < HEAD_BLOCK_SIZE_KB; j++, tmp++)
			*tmp = bias;

		for (k = 0; k < alloc - j; k++, tmp++)
			*tmp =  bias;
	}

	alloc = CHUNK;
	printf("verifying 0x%llx kbytes in %x kbyte chunks\n", kbtotal, alloc);
	gettimeofday(&t_start, NULL);
	for (i = kballoc = 0; i < numchunk; i++, kballoc += alloc) {
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		tmp = mem[i];
		if ((i % 20) == 0)
			printf("verifying %p (%lld/%lld)\n", tmp, kballoc, kbtotal);
		for (j = 0; j < HEAD_BLOCK_SIZE_KB; j++, tmp++) {
			if (*tmp != bias) {
				printf("[leading block] verifing error at %p offset 0x%x: val %x\n", 
						tmp, j, *tmp);
				exit(-1);
			}
		}
		for (k = 0; k < alloc - j; k++, tmp++) {
			if (*tmp != bias) {
				printf("[trailing block] verifing error at %p offset 0x%x: val %x truth %x\n", 
						tmp, k + HEAD_BLOCK_SIZE_KB, *tmp,  bias + 3);
				exit(-1);
			}
		}
	}
	gettimeofday(&t_end, NULL);

	timersub(&t_end, &t_start, &t_elap);

	printf("verified %lld kbytes\n", kballoc);
	fprintf(stderr, "time taken: %lu.%06lu\n", t_elap.tv_sec, t_elap.tv_usec);

	fflush(stdout);
	//usleep(2000000);
	iter++;
	goto seq_verify;
	return 0;

	///////////////////////////////////////////////////////////////////////////
rand_verify:
	alloc = CHUNK;
	bias = (iter % 5);
	printf("[%d]CHANGE BIAS VALUE %d\n", iter, bias);

	gettimeofday(&t_start, NULL);
	for (i = 0; i < 100000; i++) {
		int rand_idx = rand() % numchunk;

		tmp = mem[rand_idx];
		for (j = 0; j < HEAD_BLOCK_SIZE_KB; j++, tmp++)
			*tmp = bias;

		/*
			 for (k = 0; k < alloc - j; k++, tmp++)
		 *tmp =  bias;
		 */
	}

	gettimeofday(&t_end, NULL);

	timersub(&t_end, &t_start, &t_elap);
	fprintf(stderr, "time taken: %lu.%06lu\n", t_elap.tv_sec, t_elap.tv_usec);

	fflush(stdout);
	//usleep(2000000);
	iter++;
	goto rand_verify;
	return 0;
	}
