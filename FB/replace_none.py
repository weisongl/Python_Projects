a=[None,2,"rest",None,9,4,None]
b=[2,None,None,None]
c=[]
d=[None,None,2,"rest",None,9,4,None]
e = [None,None]

def fill_none(a):
    if len(set(a)) ==1 and a[0] == None:
        return 'List is all None'

    if len(a) == 0:
        return "List is empty"
    tmp = ''
    idx = 0
    for i in range(len(a)):# return the first not None value and idx
        if a[i] == None:
            continue
        else:
            tmp=a[i]
            # print(a[i])
            idx = i
            break
    for i in range(idx):
        a[i] = tmp

    for i in range(idx,len(a)):
        if a[i] == None:
            a[i]= a[i-1]
    return a

fill_none(a)
fill_none(b)
fill_none(c)
fill_none(d)
fill_none(e)