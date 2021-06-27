queries = [(1,1),(2,2),(3,2),(1,1),(1,1),(2,1),(3,2)]
queries[2][0]

alist = []
output = []
for i in queries:
    if i[0] == 1:
        alist.append(i[1])
    elif i[0]==2 and i[1] in alist:
        alist.remove(i[i])
    else:
        if i[1] in alist:
            output.append("YES")
        else:
            output.append('NO')

