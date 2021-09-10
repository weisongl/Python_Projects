from math import factorial

factorial(3)


def climbStairs(n) -> int:
    output = 1
    if n == 1 or n ==2 or n == 3:
        return n
    else:
        for i in range(1, n // 2 + 1):
            output += factorial(n - i) / factorial(n - 2 * i) / factorial(i)
    return int(output)


climbStairs(5)
