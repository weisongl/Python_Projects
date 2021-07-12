def getUniformIntegerCountInInterval(A, B) :
    b = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    def check_uniform(n):
        a = list(str(n))
        if n < 10:
            return 1
        if all(x == a[0] for x in a[1:]):
            return 1
        else:
            return 0
    output = 0
    for i in range(A, B + 1):
        output += check_uniform(i)
    return output

getUniformIntegerCountInInterval(75,300)

b = [1,2,3,4,5,6,7,8,9]
def check_uniform(n):
    a = list(str(n))
    if n < 10:
        return 1
    if all(x == a[0] for x in a[1:]):
        return 1
    else:
        return 0
check_uniform(77)


"""another method which I think it's way more efficient"""

def getUniformIntegerCountInInterval(A, B):
    def count_uniform(i):
        if i < 10:
            return i
        a = str(i)
        a_digit = len(a)

        # counts under the digit  (a_digit-1)*9
        # for example i = 123;   a_digit = 3,   then it would be (3-1)*9 = 27
        output = (a_digit - 1) * 9
        output += int(a[0]) - 1
        if all(int(x) >= int(a[0]) for x in a):
            print()
            output += 1
        return output

    return count_uniform(B) - count_uniform(A - 1)

getUniformIntegerCountInInterval(10,99999)
