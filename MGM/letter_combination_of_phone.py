class Solution:
    def letterCombinations(digits):
        a = list(digits)
        n = len(a)
        for i in range(n):
            a[i] = str(a[i]).replace('2', 'abc').replace('3', 'def').replace('4', 'ghi').replace('5', 'jkl').replace('6', 'mno').replace('7', 'pqrs').replace('8', 'tuv').replace('9', 'wxyz')

        output = []
        if n == 0:
            return []
        elif n == 1:
            return list(a[0])
        elif n ==2:
            for i in a[0]:
                for j in a[1]:
                    output.append(i+j)
        elif n == 3:
            for i in a[0]:
                for j in a[1]:
                    for k in a[2]:
                        output.append(i+j+k)
        elif n == 4:
            for i in a[0]:
                for j in a[1]:
                    for k in a[2]:
                        for l in a[3]:
                            output.append(i+j+k+l)
        return output