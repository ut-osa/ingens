#! /bin/bash

for p in `pgrep $1`;
do
	echo 001 > /proc/$p/hugepage_stats
done;
