
# n = int(input())
n= 15
# For numbers divisible by 3, instead of n, print Fizz
# For numbers divisible by 5, instead of n, print Buzz
# For numbers divisible by 3 and 5, just print FizzBuzz

for i in list(range(1,n+1)):
    if i%3 == 0 and i%5==0:
        print('FizzBuzz')
    elif i%3 == 0:
        print('Fizz')
    elif i%5 == 0:
        print('Buzz')
    else:
        print(i)
