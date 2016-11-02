#! /bin/bash

cat $1 | egrep -v 'procs|swpd' | awk '{swap_in += $7; swap_out += $8; io_in += $9; io_out += $10;}; 
END{
	printf "%-8s %-8s %-8s %-8s\n", "swap-in", "swap-out", "io-in", "io-out";
	printf "%-8s %-8s %-8s %-8s\n", swap_in/NR, swap_out/NR, io_in/NR, io_out/NR}'
