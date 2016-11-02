/*
 * This benchmark is designed to stress THP allocation and compaction. It does
 * not guarantee that THP allocations take place and it's up to the user to
 * monitor system activity and check that the relevant paths are used.
 */
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#define PAGESIZE getpagesize()
#define HPAGESIZE (1048576*2)

size_t total_size;
size_t thread_size;
int    nr_threads, nr_hpages;
char   *mapping;
char   **bound_start, **bound_end;
char   is_random;

/* barrier for all threads to finish initialisation on */
static pthread_barrier_t init_barrier;

static inline uint64_t timeval_to_us(struct timeval *tv)
{
    return ((uint64_t)tv->tv_sec * 1000000) + tv->tv_usec;
}

struct fault_timing {
    bool hugepage;
    struct timeval tv;
    uint64_t latency;
};

static struct fault_timing **timings;

struct arg_struct {
    int thread_idx;
    char *start;
    char *end;
};

static struct arg_struct *arguments;

static void *worker(void *args)
{
    struct arg_struct *argv = (struct arg_struct *)args;
    int  thread_idx = argv->thread_idx;
    char *start = argv->start, *p;
    char *end = argv->end;
    struct timeval tv_start, tv_end;

    size_t i, offset;
    offset = (PAGESIZE - ((size_t)start & PAGESIZE)) % PAGESIZE;
    srand(time(NULL));

    /* Wait for all threads to init */
    pthread_barrier_wait(&init_barrier);

    /* Fault the second mapping and record timings */
    if (is_random) {
        for (i = 0; i < nr_hpages; i++) {
            size_t arridx = offset + (rand()%nr_hpages) * PAGESIZE;
            gettimeofday(&tv_start, NULL);
            //start[arridx] = 1;
            memset(&start[arridx], 2, PAGESIZE);
            gettimeofday(&timings[thread_idx][i].tv, NULL);
            timings[thread_idx][i].latency = timeval_to_us(&timings[thread_idx][i].tv) - timeval_to_us(&tv_start);
        }
    }
    else {
        for (i = 0; i < nr_hpages; i++) {
            size_t arridx = offset + i * PAGESIZE;
            gettimeofday(&tv_start, NULL);
            //start[arridx] = 1;
            memset(&start[arridx], 2, PAGESIZE);
            gettimeofday(&timings[thread_idx][i].tv, NULL);
            timings[thread_idx][i].latency = timeval_to_us(&timings[thread_idx][i].tv) - timeval_to_us(&tv_start);
        }
    }

    return NULL;
}

void anon_mem_init()
{
    struct timeval tv_start, tv_end;

    gettimeofday(&tv_start, NULL);

    /* Create a large mapping */
    mapping = mmap(NULL, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (mapping == MAP_FAILED) {
        perror("mapping");
        exit(EXIT_FAILURE);
    }
    //memset(mapping, 1, total_size);

    /* You can punch holes using munmap here */

    gettimeofday(&tv_end, NULL);
    printf("anon_mem_init takes %lu.%lu sec\n",
        tv_end.tv_sec - tv_start.tv_sec,
        tv_end.tv_usec - tv_start.tv_usec);
    fflush(NULL);
}

void assign_boundary()
{
    bound_start = malloc(nr_threads * sizeof(char *));
    bound_end   = malloc(nr_threads * sizeof(char *));

    unsigned i;
    for (i = 0; i < nr_threads; i++) {
        bound_start[i] = mapping + thread_size * i;
        bound_end[i] = i == nr_threads-1? mapping + total_size - 1:
                                          mapping + thread_size * (i+1) - 1;
        // printf("bound[%d] [%p, %p)\n", i, (void *)bound_start[i], (void *)bound_end[i]);
    }
}

int main(int argc, char **argv)
{
    pthread_t *th;
    int i, j;
    if (argc != 4) {
        printf("Usage: %s [nr_threads] [total_size] [s|r]\n", argv[0]);
        exit(EXIT_FAILURE);
	}

	if (argc >= 2) {
		char *end = NULL;
		/* BOF??? */
		total_size = strtoull(argv[2], &end, 0);

		switch(*end) {
			case 'g':
			case 'G':
				total_size *= 1024;
			case 'm':
			case 'M':
				total_size *= 1024;
			case '\0':
			case 'k':
			case 'K':
				total_size *= 1024;
				break;
		}
	}
    //total_size = atol(argv[2]);


	nr_threads = atoi(argv[1]);
    is_random  = strcmp(argv[3], "r") == 0;
    printf("Running with %d thread%c\n", nr_threads, nr_threads > 1 ? 's' : ' ');

    nr_hpages   = total_size / nr_threads / PAGESIZE;
    thread_size = total_size / nr_threads;
    th = malloc(nr_threads * sizeof(pthread_t *));
    if (th == NULL) {
        printf("Unable to allocate thread structures\n");
        exit(EXIT_FAILURE);
    }

    timings = malloc(nr_threads * sizeof(struct fault_timing *));
    if (timings == NULL) {
        printf("Unable to allocate timings structure\n");
        exit(EXIT_FAILURE);
    }

    arguments = malloc(nr_threads * sizeof(struct arg_struct));
    if (arguments == NULL) {
        printf("Unable to allocate argument structure\n");
        exit(EXIT_FAILURE);
    }

    /* Initial anonymous memory */
    anon_mem_init();
    assign_boundary();

    pthread_barrier_init(&init_barrier, NULL, nr_threads);
    for (i = 0; i < nr_threads; i++) {
        timings[i] = malloc(nr_hpages * sizeof(struct fault_timing));
        if (timings[i] == NULL) {
            printf("Unable to allocate timing for thread %d\n", i);
            exit(EXIT_FAILURE);
        }
        arguments[i].thread_idx = i;
        arguments[i].start = bound_start[i];
        arguments[i].end = bound_end[i];
        if (pthread_create(&th[i], NULL, worker, (void *)&arguments[i])) {
            perror("Creating thread");
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < nr_threads; i++)
        pthread_join(th[i], NULL);
    pthread_barrier_destroy(&init_barrier);

    /* Cleanup */
    munmap(mapping, total_size);

	printf("done!\n");
	pause();
	/*
    for (i = 0; i < nr_threads; i++)
        for (j = 0; j < nr_hpages; j++)
            printf("thread[%d] fault latency %12lu timing %lu.%lu\n", i,
                timings[i][j].latency,
                timings[i][j].tv.tv_sec,
                timings[i][j].tv.tv_usec);
	*/

    return 0;
}
