"""
using counter to do that would be most efficient.
find mismatch between A and B. if one word apprears twice in A and once in B,
then include that as well
"""
output = {'A':1, 'B':3, 1:'C'}
'C' in output

from collections import Counter
# what if I can not use Counter???

def counter(A):
    # A = A.split()
    output = {}

    for i in A:
        print(i)
        if i not in output:
            output[i] = 1
        elif i in output:
            output[i] += 1
    return output

counter('How are you you'.split())



def find_mismatch(A, B):
    A = Counter(A.split())
    B = Counter(B.split())
    output = []
    print(A)
    print(B)

    for key,val in A.items():
        if key not in B.keys():
            output.append(key)
        if key in B.keys() and val > B[key]:
            output.append(key)

    for key, val in B.items():
        if key not in A.keys():
            output.append(key)
        if key in A.keys() and val > A[key]:
            output.append(key)
    return output

A = 'How are you you'
B = 'how are are you'


find_mismatch(A, B)


A = 'How are You you'
B = 'how are are you'
output = []
A = A.split()
B = B.split()

output = output + [x for x in A if x not in B] + [x for x in B if x not in A]

for i in [x for x in A if x in B] :
    if A.count(i) != B.count(i):
        output.append(i)
print(output)
