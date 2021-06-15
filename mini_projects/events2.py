checkEvents=[[1,0],[0,10]]
fillEvents = [[1,5],[0,6],[0,5]]

checkEvents=[[0,0],[1,0],[2,0],[3,0]]
fillEvents = [[3,18]]

import datetime
bt = datetime.datetime.now()

checkEvents.sort()
check = checkEvents
newCheck = check
fill = fillEvents
checkdays = []
for i in check:
    if i[0] not in checkdays:
        checkdays.append(i[0])
filldays = []
for j in fill:
    if j[0] not in filldays:
        filldays.append(j[0])

et = datetime.datetime.now()
print(et-bt)
bt = datetime.datetime.now()
# check days can't have duplicate days

# the filldays could be less than check days, so regard 0 fill on that day.
newFill = [[i, 0] for i in range(len(checkdays))]
print(newFill)
# sum each day for ill
for i in range(len(checkdays)):
    for j in fill:
        if j[0] == i:
            newFill[i][1] += j[1]
print(newFill)
output = []

for i in range(len(checkdays)):
    if i == 0:
        output.append(int(newFill[i][1]) - newCheck[i][1])
    else:
        output.append(newFill[i][1] + newCheck[i - 1][1] - newCheck[i][1])

print(*output)
et = datetime.datetime.now()
print(et-bt)