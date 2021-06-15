c = []
print(max(a), '', max(b), " ", min(a), " ", min(b))
for i in a:
    for j in b:
        c.append(abs(i - j))
        if len(c) == len(b):

n = len(b)
e = [c[i:i + n] for i in range(0, len(c), n)]
e
result = 0
for i in e:
    if min(i) > d:
        result += 1
return (result