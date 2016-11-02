#! /bin/bash

for f in `ls *.${1}.huge.*`;
do
	guest_total=`cat $f | wc -l`
	host_total=`cat $f| grep " 1"| wc -l`

	#z=`bc -l <<< "$host_total / $guest_total"`
	printf "%d %d\n" $guest_total $host_total
	z=$(echo "$host_total/$guest_total" | bc -l)
	echo $z
done
