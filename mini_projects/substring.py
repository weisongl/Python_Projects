
from collections import Counter
import math
# Driver program to test above function
s = "ifailuhkqq";
# s = "kkkk";
result = 0
single = Counter(list(s))
for values in single.values():
    if values >1:
        result += math.comb(values,2)
result


n = len(s)
arr = []
arr2 = []

for i in range(n):
    for j in range(i + 2, n):
        arr.append(s[i: j])
        arr2.append(s[i: j][::-1])

a1 = Counter(arr)
a2 = Counter(arr2)

for values in (a1&a2).values():
    result += math.comb(values+1,2)
result
1<2<3