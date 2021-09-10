s = ' Hello world I am the smartest person in the world'
s = ''
a = s.split()


a_length = [len(x) for x in a]
len(a)

print('{:.2f}'.format(round(sum(a_length) / (len(a_length)), 2)))