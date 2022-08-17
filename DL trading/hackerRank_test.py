
from collections import OrderedDict
if __name__ == "__main__":
    d = OrderedDict()

    # OrderedDictN = int(input())
    # alist = input().split(' ')
    # ' '.join(alist[:-1])

    for _ in range(int(input())):
        alist = input().split(' ')
        print(' '.join(alist[:-1]))

        d[' '.join(alist[:-1])] = int(alist[-1])

for index, value in d.items():
    print(index,value)

'x&& &&& && && x || | ||\|| x'.replace(' && ',' and ',).replace(' || ',' or ')
'x&& &&& && && x || | ||\|| x'.split(' ')

for _ in range(1):
    line = []
    for item in input().split(' '):
        if item == '&&':
            line.append(item)
        elif item == '||':
            line.append(item)
        else:
            line.append(item)
    print(' '.join(line))

    lst = ['a','b','c']
    lst_b = ['e','d']
    lst.extend(lst_b)

    for index, value in enumerate(lst):
        print(index,value)

    lst.pop()
    print(' '.join(lst))
    lst.pop()
    lst
    lst.extend(lst_b)
    lst
    lst.pop(-2)
    d = {'kevin':1,'yang':2}
    for idx, val in d.items():
        print(idx, val)
    print(d)
    n=3
    ''.join([str(i) for i in range(0, n + 1)])
    x = 1
    y = 1
    z = 2

    [print(i,j,k )for i in range(x + 1) for j in range(y + 1) for k in range(z + 1)]

