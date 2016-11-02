#! /usr/bin/python
import sys
# perf top -e dTLB-load-misses -p `pgrep java` -z -n --show-total-period -f 200


def analyze_tlb_miss(trace_file):
    i = -1
    result = []
    with open(trace_file, 'r') as f:
        for l in f.readlines():
            if len(l.split()) > 1 and \
                    l.split()[0].find('PerfTop') != -1:
                i += 1
                result.append(0)

            if len(l.split()) == 6:
                result[i] += int(l.split()[2])

    return result

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "usage: %s trace_file" % sys.argv[0]
        exit()

    result = analyze_tlb_miss(sys.argv[1])

    print result

    sum = 0
    for l in result:
        sum += int(l)

    print sum
