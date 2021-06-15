from itertools import groupby

s = list('1222311')
s
list(groupby(s))
for key, value in groupby(s):
    # print(key, ' ', value)
    print((len(list(value)), int(key)), end=' ')




