checkEvents=[[0,0],[1,0],[2,0]]
fillEvents = [[0,3],[1,2],[0,4]]

checkEvents=[[1,0],[0,10]]
fillEvents = [[1,5],[0,6],[0,5]]


fill_days = []
# get to know how many days in total
# sum total number of fill events each day.
for i in fillEvents:
    if i[0] not in fill_days:
        fill_days.append(i[0])

new_fill = [[i,0] for i in range(len(fill_days))]

for i in fillEvents:
    for j in new_fill:
        if i[0] == j[0]:
            j[1] += i[1]


check_days = []
for i in checkEvents:
    if i[0] not in check_days:
        check_days.append(i[0])


new_check = [[i, 0] for i in range(len(checkEvents))]

# print(fill_days)
# print(check_days)
# [0,0]*(len(check_days)- len(fill_days))
# fillEvents.append([0,0]*(len(check_days)- len(fill_days)))
# new_fill.append([0,0]*(len(check_days)- len(fill_days)))
if len(check_days) > len(new_fill):
    for i in range(len(new_fill),len(check_days)):
        new_fill.append([i,0])


checkEvents.sort()

for i in range(len(check_days)):
    if i==0:
        previous_stock = checkEvents[i][1]
        print(new_fill[i][1]-checkEvents[i][1])
    else:
        print(new_fill[i][1]+previous_stock-checkEvents[i][1])




[[i,0] for i in range(2)]




