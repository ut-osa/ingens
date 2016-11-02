#! /bin/bash

function get_stats() 
{
	proc=$1

	if [ -z "$proc" ]; then
		return
	fi
	name=`ps -p $1 -o comm=`

	proc_huge=`sudo cat /proc/$proc/smaps | grep AnonHuge | awk '{sum += $2}; END {print sum}'`
	proc_total=`sudo cat /proc/$proc/status | grep VmRSS | awk '{print $2}'`

	printf "%s (%s): %u %u\n" "$name" "$1" "$proc_huge" "$proc_total"
}

for pid in `pgrep mcf`
do
	get_stats $pid
done;

for pid in `pgrep canneal`
do
	get_stats $pid
done;

for pid in `pgrep tunkrank`
do
	get_stats $pid
done;

get_stats `pgrep mempressure`
get_stats `pgrep frag_normal`
get_stats `pgrep redis`

for pid in `pgrep $1`
do
	get_stats $pid
done;

for pid in `pgrep php`
do
	get_stats $pid
done;

for pid in `pgrep nginx`
do
	get_stats $pid
done;

for pid in `pgrep memcached`
do
	get_stats $pid
done;
