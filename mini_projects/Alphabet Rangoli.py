
# sample  2*size -1 lines
# ----c----
# --c-b-c--
# c-b-a-b-c
# --c-b-c--
# ----c----
import string
def print_rangoli(size):
    # your code goes here
    # if size ==1:
    #     return('a')
    #     break
    alphabet = list(string.ascii_lowercase)
    n = size
    a = 'a'
    for i in alphabet[1:n]:
        a = a + '-' + str(i)


    reversed_a = a[::-1][:-1]


    middle_line = reversed_a + a

    one_line_above_middle = '-'*2 + reversed_a[:-2] + a[2:]+'-'*2
    two_line_above_middle = '-'*4 + reversed_a[:-4] + a[4:] + '-'*4

    # print(a)
    # print(reversed_a)
    # print(middle_line)
    # print(one_line_above_middle)
    # print(two_line_above_middle)



    for i in range(1,n):
        print('-'*2*(n-i)+ reversed_a[:-2*(n-i)]+a[2*(n-i):] + '-'*2*(n-i))

    print(reversed_a + a)

    for i in range(n-1,0,-1):
        print('-'*2*(n-i)+ reversed_a[:-2*(n-i)]+a[2*(n-i):] + '-'*2*(n-i))


print_rangoli(27)