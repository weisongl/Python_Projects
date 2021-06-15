import collections
a_list = [1, 2, 3, 4, 5, 99, 1, 2, 3, 4, 5]
def select_single(a_list):
    occurrences = collections.Counter(a_list)
    for items, values in occurrences.items():
        if values == 1:
            print(items)
select_single(a_list);


import collections
##a_list = [1, 2, 3, 4, 5, 99, 1, 2, 3, 4, 5]
a_list = input().replace(" ","").split(',')
occurrences = collections.Counter(a_list)
occurrences
for items, values in occurrences.items():
    if values == 1:
        print(items);


a = [10, 11, 12, 13, 14, 15]
[a[i] for i in (1, 2, 5)]
