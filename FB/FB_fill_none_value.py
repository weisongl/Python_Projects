def fill_None(a):
    n = len(a)
    if n == 0:
        return "List is empty"
    if a[0] is None and len(set(a)) == 1:
        return 'List is all None'

    for i in range(n - 1):
        if a[i] is not None and a[i + 1] is None:
            a[i + 1] = a[i]
    return a


a = [1, None, 1, 2, None]
a = []
a = [None, 1, 1, None]
a = [None]

fill_None(a)
"""
edge case, len(a) == 0 
a only has None
first new are none. 
"""
