def fibonacci(n):
    if n == 0:
        print(0)
    elif n == 1 or n ==2:
        print(1)
    else:
        f = [0] * (n+1)
        f[0] = 0
        f[1] = 1
        f[2] = 1
        for i in range(n - 1):
            f[i+2] = f[i+1] + f[i]
        print(f[n])

fibonacci(30)