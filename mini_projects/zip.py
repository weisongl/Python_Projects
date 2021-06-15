# N, K = map(int, input().split())
# score = []
# for _ in range(K):
#     score.append(list(map(float, input().split())))
score = [ [i+0.1] for i in range(10)]
score
K=10
for item in list(zip(*score)):
    sum = 0
    print(item)
    for j in item:
        sum += j
    print(round(sum / K, 1))

"ABCDEFG"[:-2]
# from  datetime import datetime
# f = '%a %d %b %Y %H:%M:%S %z'
# t1 = 'Sat 02 May 2015 19:54:36 +0530'
# t2= 'Fri 01 May 2015 13:54:36 -0000'
# d1 = datetime.strptime(t1, f)
# d2 = datetime.strptime(t2, f)
# (d1-d2).total_seconds()


import collections

collection = collections.Counter('aabbdddd')
print(collection)
for key, val in collection.items():
    print(key,' ',val)