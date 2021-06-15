import collections
# alist = input()
#list = list('())([]{}')

alist= list(input())
alist[0]
#alist=  list('()[]{}')
# ([{}])
# ([]{})#
#
# ([)]
# ([]
# [])
# ([})

#
# seperate the three type of delimeter (), [],{}
# left and right delimiter should have the same number.
# left delimiter should be always left of the right delimeter.
# compare the index number of all left delimiters with the index number of right delimiters.
# example ([]{})() would be seperated as three lists
# ()()  and [] and {}
# (): index for "(" would be [0,2] and index for ")" would be (1,3). 0<1 and 2<3
t1 = []
t2 = []
t3 = []
for i in alist:
    if i == '(' or i == ')':
        t1.append(i)
    elif i == '[' or i == ']':
        t2.append(i)
    else:
        t3.append(i)


collections.Counter(t1)

t1_collection = collections.Counter(t1)
t2_collection = collections.Counter(t2)
t3_collection = collections.Counter(t3)

even_flag = (t1_collection['('] ==t1_collection[')'] ) and (t2_collection['['] == t2_collection[']'] ) and (t3_collection['{'] ==t3_collection['}'] )

result = True

if not even_flag:
    #print(even_flag)
    result = even_flag


t11 = [i for i, x in enumerate(t1) if x == "("]
t12 = [i for i, x in enumerate(t1) if x == ")"]
t11
t12

for i,j in zip(t11,t12):
    if i > j:
        print(False)
        result = False
        break
    else:
        continue


t21 = [i for i, x in enumerate(t2) if x == "["]
t22 = [i for i, x in enumerate(t2) if x == "]"]
for i,j in zip(t21,t22):
    if i > j:
        print(False)
        result = False
        break
    else:
        continue

t31 = [i for i, x in enumerate(t3) if x == "{"]
t32 = [i for i, x in enumerate(t3) if x == "}"]

for i,j in zip(t31,t32):
    if i > j:
        print(False)
        result = False
        break
    else:
        continue

print(result)