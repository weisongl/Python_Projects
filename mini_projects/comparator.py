expenditure  = [1,2,3,4,4]
expenditure  = [2, 3, 4, 2, 3, 6, 8, 4, 5]
# expenditure  = [10,20,30,40,50]
d = 3

n = len(expenditure)
output = 0
for i in range(n - d ):  # n=5 d = 3 i in range(2) 0 1   # n = 5 d = 4
    checks = expenditure[i:i + d].copy()
    checks.sort()

    l_checks = len(checks)
    print(checks)
    median = 0
    # print(i,d)
    if l_checks % 2 == 0:
        median = ( checks[int((l_checks - 1)/2)] + checks[int(l_checks/2)])/2
    else:
        median = checks[int((l_checks - 1) / 2)]
    print(median)
    if expenditure[i + d] >= 2 * median:
        output += 1
    print(expenditure[i + d])
print (output)