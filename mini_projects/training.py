import collections
a_list = [10, 20, 20, 10, 10, 30, 50, 10, 20]

occurrences = collections.Counter(a_list)
occurrences

count = 0
round(3/2)

for items,  values in occurrences.items():
    count += values%2
    print(values%2)
print(count)


# !/bin/python3

import math
import os
import random
import re
import sys

#
# Complete the 'sockMerchant' function below.
#
# The function is expected to return an INTEGER.
# The function accepts following parameters:
#  1. INTEGER n
#  2. INTEGER_ARRAY ar
#
import collections


def sockMerchant(n, ar):
    # Write your code here

    occurrences = collections.Counter(ar)
    occurrences

    n = 0

    for items, values in occurrences.items():
        n += round(int(values) / 2)
    return (n)


if __name__ == '__main__':
    fptr = open(os.environ['OUTPUT_PATH'], 'w')

    n = int(input().strip())

    ar = list(map(int, input().rstrip().split()))

    result = sockMerchant(n, ar)

    fptr.write(str(result) + '\n')

    fptr.close()
