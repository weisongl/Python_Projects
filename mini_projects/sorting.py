arr = [2, 1, 3, 1, 2]
arr = [1, 1, 1, 2, 2]
arr = [2,3,1]


sort_a = arr.copy()
sort_a.sort()
for i, j in zip(sort_a, arr):
    print(i, j)

n = len(arr)
swap = 0
import numpy as np
while not (np.array_equal(arr, sort_a)):
    # n -= 1
    i = 0
    while i < n-1:
        if arr[i] > arr[i + 1]:
            arr[i], arr[i + 1] = arr[i + 1], arr[i]
            print(i, arr)
            swap += 1
        i += 1

print(swap)
