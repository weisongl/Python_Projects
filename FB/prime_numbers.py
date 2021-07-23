def is_prime(n):
    if n ==1:
        return False
    if n == 2:
        return True
    if n%2 == 0:
        return False
    for i in range(3,n,2):
        # print(i)
        if n%i == 0:
            return False

    return True

def get_prime_list(n):
    output = '2'
    if n==1:
        return 'No valid input'
    elif n==2:
        return '2'
    else:
        for i in range(3, n+1):
            if is_prime(i):
                output = output + '&' + str(i)
    return(output)

get_prime_list(1000)


def is_prime(n):
    if n == 1:
        return False
    if n == 2:
        return True

    output = True

    for i in range(2, n):
        if n % i == 0:
            output = False
            break
    return output

for i in range(1,10):
    print(i,is_prime(i))