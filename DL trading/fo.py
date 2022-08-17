nums = [2,2,1]
d = {}
for i in nums:
    if i not in d:
        d[i] = 1
    else:
        d[i] += 1
d.values()
d.keys()
d.values()