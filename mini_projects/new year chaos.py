s = '1 2 5 3 4 7 8 6'
q = list(map(int, s.rstrip().split()))
q

# for idx, val in enumerate(q):
#     print(idx, val)

d = dict(enumerate(q, 1))
print(d)
count = 0
for i in range(len(d), 1, -1):
    print(d,' ', i)
    if d[i] == i:
        continue
    if d[i - 1] == i:
        d[i - 1] = d[i]
        # print(d)
        # break
        count += 1
    elif d[i - 2] == i:
        d[i - 2], d[i - 1] = d[i - 1], d[i]
        count += 2
    else:
        print("Too chaotic")
print(count)
