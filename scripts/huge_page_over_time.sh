#! /bin/bash
i=0
sleep_int=5

if [[ $# > 0 ]];
then
	file="$1"
else
	file="tmp"
fi

free > free.$file
cat /proc/vmstat | grep thp > thp_before.$file
cat /proc/vmstat | grep compact > compact_before.$file
#sudo perf record -a -e dTLB-loads -e dTLB-load-misses -e dTLB-stores -e dTLB-store-misses -o perf.$file &

control_c()
{
	cat /proc/vmstat | grep thp > thp_after.$file
	cat /proc/vmstat | grep compact > compact_after.$file
	#sudo pkill perf
	exit $?
}

trap control_c SIGINT

while true;
do
	huge_pages=`cat /proc/meminfo | grep AnonHugePages | awk '{print $2}'`
	frag_idx=`./pagealloc-extfrag | awk '{print $2}'`
	printf "%u %u %f\n" "$i" "$huge_pages" "$frag_idx"  | tee -a huge.$file
	sleep $sleep_int
	i=$[$i+$sleep_int]
done
