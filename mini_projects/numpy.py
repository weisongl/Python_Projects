import numpy as np

# alist = list(map(float,input().split()))

alist= [1.1,2.3,5.5]


print(np.floor(alist))
print(np.ceil(alist))

print(np.rint(alist))

import numpy


N, M = map(int, input().split())
ar=[]
for _ in range(N):
    ar.append(list(map(int, input().split())))
ar=alist
print(numpy.prod(numpy.sum(ar, axis=0)))



import numpy as np
N,M = map(int,input().split())
ar =[]
for _ in range(N):
    ar.append(list(map(int,input().split())))


np.max(np.min(ar,axis=1))