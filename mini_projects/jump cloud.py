c = [0,0,0,1,0,0]
c =[0,0,1,0,0,1,0]

result = 0
while len(c) >= 3:
    if c[2] == 1:
        result += 2
        c = c[3:]
        print(c)
    else:
        result += 1
        c = c[2:]
        print(c)

if len(c) ==2:
    result +=1
print(result)