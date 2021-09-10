from collections import Counter
s= 'missisipi'
s = list(s)
s = Counter(s)
s

"""
Now try not to use counter. 
"""

def find_occur(a,s):
    a = list(a)
    output = 0
    for i in a:
        if i==s:
            output +=1
    return output

a = "missisipi what's that"
s = 's'
find_occur(a, s)

Counter(a)[s]



# thinking about a different case:
# count the possible occure subsets?
# another thing I'm interested is to get all the subset:
a = 'abcdefghijklmnopqrstuvwxyz'
a = '123456'
n = len(a)
output = []
for j in range(1,n+1): #len of sub, range from 1 to n
    for i in range(n-j+1):
        # starting place of sub, range from 0 to n-j+1
        output.append(a[i:i+j])
print(output)



