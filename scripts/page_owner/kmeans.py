#! /usr/bin/python

import sys
import numpy as np

from sklearn.cluster import KMeans

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


def extract_data(data_file, PG_flag=''):
    X = np.zeros((0, 1), int)
    with open(data_file) as f:
        for l in f.xreadlines():
            if l.find("PFN") >= 0:
                pfn = int(l.split(' ')[1])
                if PG_flag:
                    if l.find(PG_flag) >= 0:
                        X = np.append(X, [[pfn]], axis=0)
                else:
                    X = np.append(X, [[pfn]], axis=0)

    return X

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage %s <page_owner dump file>\n" % sys.argv[0])
        exit(-1)

    print("Start extracting data")
    X = extract_data(sys.argv[1], PG_flag='S')

    kmeans = KMeans(n_clusters=20, max_iter=400, n_jobs=-1, init="k-means++")

    print("Start training")
    kmeans.fit(X)
    '''
    np.set_printoptions(threshold='nan')
    labels = kmeans.labels_
    '''
    print kmeans.inertia_
