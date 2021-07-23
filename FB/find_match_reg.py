
# using the re module
import re
def isMatch(s,a):
    output = []
    for i in a:
        output.append(bool(re.match(s,i)))
    return output

isMatch('c.t', ['cat', 'bte', 'art', 'drat', 'dart', 'drab'])

# use without the re module
s = 'c.t'
a = ['cat', 'bte', 'art', 'drat', 'dart', 'drab']

sn = len(s)
output = []
for i in a:
    n = len(i)
    if i<n:
        output.append(False)
    if s in i:
        output.append(True)
    for j in range(n-sn):
        i[j,j+sn]









