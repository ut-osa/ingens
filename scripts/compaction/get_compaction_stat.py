#! /usr/bin/python
import sys


def analyze_trace(trace_file):
    i = 0
    result = []
    with open(trace_file, 'r') as f:
        for l in f.readlines():
            if l.split()[4].find('mm_compaction_begin') != -1:
                result.append(0)
            elif l.split()[4].find('mm_compaction_end') != -1:
                i += 1
            elif l.split()[4].find('mm_compaction_migratepages') != -1:
                result[i] += int(l.split()[5].split('=')[1])

    return result

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "usage: %s trace_file" % sys.argv[0]
        exit()

    result = analyze_trace(sys.argv[1])

    zero = 0
    total = 0
    for l in result:
        if l != 0:
            print result.index(l),
            print l
            total += l
        else:
            zero += 1

    print "total migrated page: %ld size: %.3lf GB" % (total, 4 * float(total) / (1024*1024))
    print "zero migration: %ld" % zero
