#! /usr/bin/python

import sys
import collections
import matplotlib as mpl
# make it work without X server.
# only purpose for generating pdf file
mpl.use('Agg')
import matplotlib.pyplot as plt

migration_type = ["MIGRATE_UNMOVABLE", "MIGRATE_RECLAIMABLE", "MIGRATE_MOVABLE", "MIGRATE_PCPTYPES", "MIGRATE_RESERVE", "MIGRATE_CMA", "MIGRATE_ISOLATE"]

'''
Page flags
PageLocked(page)  ? "K" : " ",
PageError(page)   ? "E" : " ",
PageReferenced(page)  ? "R" : " ",
PageUptodate(page)  ? "U" : " ",
PageDirty(page)   ? "D" : " ",
PageLRU(page)   ? "L" : " ",
PageActive(page)  ? "A" : " ",
PageSlab(page)    ? "S" : " ",
PageWriteback(page) ? "W" : " ",
PageCompound(page)  ? "C" : " ",
PageSwapCache(page) ? "B" : " ",
PageMappedToDisk(page)  ? "M" : " ")
'''

''' parsing data structure
{ PFN:x , {order:, flag: [ ], ... } }
...
'''
def extract_data(trace_file):
    line = 0
    result = {}
    with open(trace_file) as f:
        for l in f.xreadlines():
            line += 1
            if l.find("Page allocated") >= 0:
                order = int(l.split(' ')[4].rstrip(','))
            elif l.find("PFN") >= 0:
                pfn = int(l.split(' ')[1])
                result[pfn] = {}
                result[pfn]["order"] = order

    return result


def draw_data(fig, data, pos):
    axprops = dict(xticks=[], yticks=[])
    # barprops = dict(aspect='auto', cmap=plt.cm.binary, interpolation='nearest')
    barprops = dict(aspect='auto', cmap=plt.cm.binary, interpolation='hanning')

    ordered_data = collections.OrderedDict(sorted(data.items()))

    last_key, last_value = list(ordered_data.items())[-1]
    alloc_map = [0] * (last_key + last_value["order"] + 1)

    for k, v in ordered_data.iteritems():
        order = v["order"]
        try:
            for l in range(0, 1 << order):
                alloc_map[k+l] = 1
        except:
            print k+l

    # print alloc_map
    # rect = tuple([0.0, 0.0, 1, 1])
    ax = fig.add_axes(pos, **axprops)
    ax.imshow([alloc_map], **barprops)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage %s <page_owner dump file1> <file2>\n" % sys.argv[0])
        exit(-1)

    fig = plt.figure(figsize=(90, 10))

    result = extract_data(sys.argv[1])
    rect = tuple([0.01, 0.5, 1, 0.40])
    draw_data(fig, result, rect)

    result = extract_data(sys.argv[2])
    rect = tuple([0.01, 0.05, 1, 0.40])
    draw_data(fig, result, rect)

    # fig.savefig(sys.argv[1]+'.pdf')
    fig.savefig('result.pdf')
    # plt.show()
