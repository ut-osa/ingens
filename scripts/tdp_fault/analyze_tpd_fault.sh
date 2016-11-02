#! /bin/bash

if [[ "$#" < "1" ]]; then
	echo "$0 dump_file_to_analyze"
	exit
fi

cat $1 | grep -v PerfTop | grep kernel | awk '{sum += $2}; END{print sum}'
