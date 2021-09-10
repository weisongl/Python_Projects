data = [['A', 1, 100]
    , ['A', 2, 110]
    , ['A', 3, 120]
    , ['A', 3, 130]
    , ['A', 4, 150]
    , ['A', 5, 170]
    , ['B', 1, 100]
    , ['B', 2, 110]
    , ['B', 3, 120]
    , ['B', 3, 130]
    , ['B', 4, 150]
    , ['B', 5, 170]]

output = {}
stk = 0
for sub in data:
    print(sub)
    if sub[0] not in output.keys():
        output[sub[0]] = []
        stk = sub[0]
        pre_act = sub[1]
        pre_time = sub[2]
    if sub[1] == 1 or sub[1] == pre_act:
        continue
    else:
        output[stk].append(sub[2]-pre_time)
        pre_time = sub[2]
        pre_act = sub[1]









