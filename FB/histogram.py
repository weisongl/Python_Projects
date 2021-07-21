a = [2,3,4,5]
for i in a:
    print('*'*i)

a = [2,4,5,7,10,19]
n = len(a)
amax = max(a)
for i in range(amax):
    arr = []
    for j in range(n):
        arr.append(1 if a[j] - (amax-i) >= 0 else 0)
    print(*['*'*x + ' '*(1-x) for x in arr] )