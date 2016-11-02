#! /bin/bash

if [[ "$#" < "1" ]]; then
	echo "$0 dump_file_name"
	exit
fi

sudo perf top -e kvm:kvm_page_fault -a -n -z > $1
