## Ingens 

Coordinated and Efficient Huge Page Management system.

Details are in a OSDI paper:
http://www.cs.utexas.edu/~yjkwon/pdf/kwon16osdi-ingens.pdf

## Components

linux-4.3.0-ingens : Ingens Linux kernel

ingens.diff : Kernel (based on v4.3.0) patches of Ingens

scripts : experiment scripts

programs : Various programs and tools for experiments

benchmarks : some benchmarks used in the paper (To be uploaded)

## Ingens kernel build.

An example of configuration file is "memory.config" in linux-4.3-ingens.

Ingens uses linux idle page tracking. 
(http://lxr.free-electrons.com/source/Documentation/vm/idle_page_tracking.txt)

Make sure to set
CONFIG_IDLE_PAGE_TRACKING=y
in your kbuild configuration.

## Parameters

List of configurable policy parameters 

#### /sys/kernel/mm/transparent_hugepage/ingens/

- deferred_mode

0 : Unmodified Linux

1 : Ingens without sampling address for access bit tracking

2 : Ingens with sampling address for access bit tracking

3 : Frequency-based promotion; Experimental and Unused

e.g., echo 2 > /sys/kernel/mm/transparent_hugepage/ingens/deferred_mode

- util_threshold

utilization threshold (0 < util_threshold <= 100)

- scan_sleep_millisecs

Sleep interval for each access bit profiling in milliseconds

- compact_sleep_millisecs

Sleep interval for proactive compaction in milliseconds

0 : disable proactive compaction

- fairness 

0 : Turn off huge page promotion

1 : Enable fair huge page promotion

#### /sys/kernel/mm/ksm/
- run

0 : Disable identical page sharing

1 : Linux identical page sharing

2 : Huge identical page sharing

3 : Huge page reservation based page sharing (experimental)

4 : Ingens coordinated page sharing

### Experimental
- /sys/kernel/mm/transparent_hugepage/ingens/distance_divisor
- /sys/kernel/mm/transparent_hugepage/ingens/aggregation_sleep_millisecs

## Ingens features

#### Used features
- Asynchronous promotion
- Utilization-based promotion
- Fair huge page promotion
- Identical Huge page sharing
- Coordinated huge page sharing
- Proactive compaction
- Hot/cold page identification
- Huge page aligned mmap
- TCmalloc improvement for huge page allocation

#### Experimental features
- Fair LRU eviction for swapping
- Guest physical page aggregration
- Auto-ballooning using memory pressure notification API

## Contributors

Youngjin Kwon (yjkwon@cs.utexas.edu)

Hangchen Yu (hyu@cs.utexas.edu)

## License
GPLv2 License
