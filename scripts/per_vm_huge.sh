#! /bin/bash

function get_stats() 
{
	vm=`pgrep qemu -a | grep $1 | awk '{print $1}'`

	if [ -z "$vm" ]; then
		return
	fi

	vm_huge=`sudo cat /proc/$vm/smaps | grep AnonHuge | awk '{sum += $2}; END {print sum}'`
	vm_total=`sudo cat /proc/$vm/status | grep VmRSS | awk '{print $2}'`

	p=$(echo "$vm_huge/$vm_total" | bc -l)
	printf "%s (-): %u %u %f\n" "$1" "$vm_huge" "$vm_total" "$p"

	#sudo sh -c "echo 0100 > /proc/$vm/hugepage_stats"
	#sudo cat /proc/$vm/hugepage_stats
}

get_stats vm1
get_stats vm2
get_stats vm3
get_stats hadoop
get_stats workload
get_stats spark
get_stats web
get_stats db
