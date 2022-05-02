
from collections import OrderedDict
if __name__ == "__main__":
    d = OrderedDict()

    # OrderedDictN = int(input())
    # alist = input().split(' ')
    # ' '.join(alist[:-1])

    for _ in range(int(input())):
        alist = input().split(' ')
        print(' '.join(alist[:-1]))

        d[' '.join(alist[:-1])] += int(alist[-1])

for index, value in d.items():
    print(index,value)