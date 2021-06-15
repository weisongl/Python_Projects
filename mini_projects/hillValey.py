# steps = int(input())
# path = input()

path = 'UDDDUDUU'
steps = 8

path = 'UDDDUDUUDU'
steps = 10

n = steps
value = []
for i in list(path):
    if i =='U':
        value.append(1)
    else:
        value.append(-1)
number_of_valey = 0
sum = 0
for i in value:
    sum += i
    if sum == 0 and i == 1:
        number_of_valey +=1

print(number_of_valey)


