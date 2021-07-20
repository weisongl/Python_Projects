# Write your code here
def steps(N, F, P):
    n = N
    f = F
    a = [0] * n
    P = [x-1 for x in P]
    for i in range(n):
        if i in P:
            a[i] = 1
    # print(a)
    output = 0
    break_flag = False
    for i in range(n - 1):
        if break_flag:
            break
        print(a)
        print(output)
        if a[i] == 0:
            continue
        for j in range(i + 1, n):
            if j == n - 1:
                # break the whole loop
                # break_flag = True
                break
            if a[j] == 0:
                a[i], a[j] = a[j], a[i]
                output += 1
                continue
            if a[j] == 1:
                continue
    # print(output)
    output += F
    return output


P = [1]
F = 1
N = 3


N = 20
F = 5
P = [5, 2, 4,10,18]
steps(N, F, P)
