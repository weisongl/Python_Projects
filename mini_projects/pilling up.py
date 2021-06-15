# Enter your code here. Read input from STDIN. Print output to STDOUT

T = int(input())

A = [[]] * T

for i in range(T):
    n = int(input())
    A[i] = list(map(int, input().split()))
print(A)
B = A.copy()

A = [[4, 3, 2, 1, 3, 4], [1, 3, 2]]
for sub in A:
    print(sub)
    for i in range(len(sub)):
        result = 'Yes'
        m = max(sub)
        print(m)
        if m > max(sub[0], sub[-1]):
            result='No'
        elif m <= max(sub[0], sub[-1]):
            if sub[0] >= sub[-1]:
                del (sub[0])
            else:
                del (sub[-1])
    print(result)


for sub in A:
    print(sub)

from collections import deque
d = deque()
print(d)