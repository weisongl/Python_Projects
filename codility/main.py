A = [5,6,3,4,3,1]
n = len(A)
A = [100,50,40,20]
# if A == sorted(A) or A[::-1] == sorted(A):


a = A[1:-1]
if A[-1] > A[0]:
    while a != sorted(a):
        for i in range(1, n - 1):
            if A[i - 1] <= A[i] <= A[i + 1]:
                continue
            elif A[i] > A[i - 1] and A[i] > A[i + 1]:
                A[i] -= 1
            elif A[i] < A[i - 1] and A[i] < A[i + 1]:
                A[i] += 1
        a = A[1:-1]
        print(a)
else:
    while a != reversed(sorted(a)):
        for i in range(1, n - 1):
            if A[i - 1] <= A[i] <= A[i + 1]:
                continue
            elif A[i] > A[i - 1] and A[i] > A[i + 1]:
                A[i] -= 1
            elif A[i] < A[i - 1] and A[i] < A[i + 1]:
                A[i] += 1
    print(a)
    a = A[1:-1]
for i in range(100):
    print(i,hex(i))

