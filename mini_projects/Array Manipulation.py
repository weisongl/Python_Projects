n = 10

queries = [[1, 2, 3], [2, 3, 4]]
arr = [0 for _ in range(n)]
arr2 = [1 for _ in range(n)]
for i in queries:
      a = i[0]
      b = i[1]
      k = i[2]
      for j in range(a-1,b):
          arr[j] +=k

for a,b,k in queries:
    print(a,b,k)
