#######################   compare two  strings  ##########################
# Given two sentences,
# you have to print the words those are not present in
# either of the sentences.
# (If one word is present twice in 1st sentence
# but not present in 2nd sentence then you have to print that word too)

from collections import Counter
A = "HOW ARE you YOU"
B = "How are you"
A = set(A.split())
B = set(B.split())
(A-B).union(B-A)
A = "HOW ARE you YOU"
B = "How are you"
for i,j in zip(A.split(),B.split()):
    if i != j:
        print(i,j)


# new method. using counter.
from collections import Counter
A = "HOW ARE you you you"
B = "How are you"
A = Counter(A.split())
B = Counter(B.split())
output = []
for idx, val in A.items():
    # print(idx, val)
    if idx not in B.keys():
        output.append(idx)
    if idx in B.keys() and val > B[idx]:
        output.append(idx)

for idx, val in B.items():
    print(idx, val)
    if idx not in A.keys():
        output.append(idx)
    if idx in A.keys() and val > A[idx]:
        print(val, idx)
        output.append(idx)
print(output)





#######################   get the nth highest ################################
def count(a):
    output = {}
    for i in list(a):
        if i not in output.keys():
            output[i] = 1
        else:
            output[i] = output[i]+ 1
    return output

count('mmissisipsi')



from collections import Counter
counter = Counter('mmissisipsi')
counter['s']
type(dict(counter))

a = list(set(counter.values()))
a.sort()
del a[-1:]
a[-1]
if len(a) == 0: # mean all vals are the same, no nth high values, n==0 also no valid
    print('do something')
output = [idx for idx,val in counter.items() if val == a[-1]]
output[0]
#######################   get the nth highest ################################



#######################   balance the array ################################
a = [4, 5, 11, 5, 6, 11]
from collections import Counter
counter = Counter(a)
max_fre = max(counter.values())
for idx, val in counter.items():
    if val < max_fre:
        print('We need {} if element {}.'.format(max_fre-val, idx))


#######################   balance the array ################################