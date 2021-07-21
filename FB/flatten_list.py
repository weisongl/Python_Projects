a = [1,[2],3,3,[1234,[12,2,5,6]]]
a = str(a).replace('[','').replace(']','').replace(',',' ')
list(map(int,a.split()))

a = [[1, 2, 3, 4],3 ,[5, 6, 7], [8, 9, 10]]
def flat_list(a):
    output = []
    for sub in a:
        if type(sub) == list:
            for i in sub:
                output.append(i)
        else:
            output.append(sub)
    return output
flat_list(a)