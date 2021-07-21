a = [1, None, 1, 2, None]

start_idx = 0
start_val = ''
for idx, val in enumerate(a):
    if val is not None:
        start_idx = idx
        start_val  = val
        break
print(start_idx)

tmp = a[0]
for i in range(1,len(a)):
    if a[i] == None:
        print(a[i])
        a[i] = tmp
    tmp = a[i]

print(a)



import random
random.randrange(1,100)


a = [0,1,2,3,4,5]

[val for idx, val in enumerate(a,1) if idx %2 == 0]
a=[1,1,1]
tmp = a[0]

for i in range(1,len(a)):
    tmp += a[i]
    a[i] = tmp

i
list(map(int,str(133)))


a = [1, 1, 5, 5, 10, 8, 7]
a = [-10, -4, -2, -4, -2, 0]
a.sort()
a
a = a[1:-1]
'{:.2f}'.format(sum(a)//len(a))