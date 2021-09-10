a = [[1,2],[1,3],[2,4],[4],[6],[5,3]]

alist = str(a).replace('[','').replace(']','').replace(',',' ').split()

def find_friend(a):
    alist = set( str(a).replace('[','').replace(']','').replace(',',' ').split())
    output = {}
    for i in alist:
        output[i] = 0
    # print(output)
    for i in a:
        # print(i)
        if len(i) ==2:
            for j in i:
                # print(j)
                output[str(j)] = output[str(j)] + 1
    print(output)

find_friend(a)