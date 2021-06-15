string = 'AABCAAADA'
k = 3
n = len(string)
# dictionary_name.fromkeys(keys, value)
for i in range(1, k + 1):
    print(i)
    print(*set(string[int(n * (i - 1) / k):int(n * i / k)]), sep='')

i = 1
print(*set(string[int(n * i / k):int(n * (i + 1) / k)]))

res = []
[res.append(x) for x in string[int(n * (i - 1) / k):int(n * i / k)] if x not in res]
res = []
for j in string[int(n * (i - 1) / k):int(n * i / k)]:
    print(j)
    if j not in res:
        res.append(j)


res