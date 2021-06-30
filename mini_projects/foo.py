arr = [1520,5857,4094,4157,3902,822]
arr.sort()
print(arr)
k=5
arr.sort()
n = len(arr)
for i in range(n - k + 1):  # if n = 5 and k =2
    output = arr[k - 1] - arr[0]
    if output > arr[i + k - 1] - arr[i]:
        output = arr[i + k - 1] - arr[i]
    print(arr[i + k - 1] , arr[i])
    print(output)