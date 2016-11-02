#! /bin/bash

function get_stats() 
{
	proc=$1

	if [ -z "$proc" ]; then
		return
	fi

	proc_swap=`sudo cat /proc/$proc/status | grep VmSwap | awk '{print $2}'`
	proc_total=`sudo cat /proc/$proc/status | grep VmRSS | awk '{print $2}'`

	name=`cat /proc/$pid/cmdline | awk 'BEGIN {FS="\0"} {print $1}'`
	printf "%s ( %s ): %u %u\n" "$name" "$1" "$proc_swap" "$proc_total"
}

for pid in `pgrep $1`
do
	get_stats $pid
done;
