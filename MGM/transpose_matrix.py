a = [[1,2],[3,4],[5,6]]
print(a)

m = len(a)
n = len(a[0])
print(m,n)

a[:-1]

[ [a[i][j] for i in range(len(a))] for j in range(len(a[0])) ]
' test'.lstrip(' ')

'01'.isdigit()

for i in '42'.split(' ')[0]:
    print(i)
'+12'.isdigit()
output = "    0000000000000   ".lstrip().split(' ')[0]

int( str(output).lstrip('0'))

for sub in 'abc1':
    print(sub)

list('  what\'s that 1234')