a =  [['A','B'],['A','C'],['B','D'],['B','C'],['R','M'], ['S'],['P'], ['A']]
output = {}
for pair in a:
    if len(pair) == 2:
        for i in pair:
            print(i)
            if i not in output.keys():
                output[i] = 1
            else:
                output[i] = output[i] + 1
    else:
        if pair[0] not in output.keys():
            output[pair[0]] = 0
print(output)