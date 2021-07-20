#this is a classes to create all the subclass of a list
from collections import Counter

a = [1,2,3,2,1]
b = [3,2,1,4,7]

def getsub(a):
    n = len(a)
    output = []
    for i in range(n):
        for j in range(i+1,n+1):
            # print(output)
            # print(a[i:j])
            if a[i:j] not in output:
                output.append(''.join([str(elem) for elem in a[i:j]]))
    return (output)

ac = set(getsub(a))
bc = set(getsub(b))

max(ac&bc)