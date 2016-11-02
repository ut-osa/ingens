#! /bin/bash

printf "%-20s %8d\n" "PageLocked" `grep K $1 | wc -l`
printf "%-20s %8d\n" "PageError" `grep E $1 | wc -l`
printf "%-20s %8d\n" "PageReferenced" `grep R $1 | wc -l`
printf "%-20s %8d\n" "PageUptodate" `grep U $1 | wc -l`
printf "%-20s %8d\n" "PageDirty" `grep D $1 | wc -l`
printf "%-20s %8d\n" "PageActive" `grep A $1 | wc -l`
printf "%-20s %8d\n" "PageLRU" `grep L $1 | wc -l`
printf "%-20s %8d\n" "PageSlab" `grep S $1 | wc -l`
printf "%-20s %8d\n" "PageWriteback" `grep W $1 | wc -l`
printf "%-20s %8d\n" "PageCompound" `grep C $1 | wc -l`
# printf "%-20s %8d\n" "PageSwapCache" `grep B $1 | wc -l`
printf "%-20s %8d\n" "PageMappedtoDisk" `grep M $1 | wc -l`
