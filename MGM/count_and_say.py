from itertools import groupby

for x ,y in groupby('abbbbb'):
    print(x)
    print(sum(1 for _ in y))
    # for i in y:
    #     print(i)



def countAndSay(n):
    num = "1"
    for i in range(n-1):
        new_num = ""
        for x, y in groupby(num):
            print(x,y)
            new_num += str(sum(1 for _ in y))+x
        num = new_num
    return num


countAndSay(3)
for x, y in groupby("112"):
    print(x)
    for i in y:
        print(i)