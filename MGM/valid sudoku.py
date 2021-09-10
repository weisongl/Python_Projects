import numpy
def isValidSudoku(a):

    tmp = ['1', '2', '3', '4', '5', '6', '7', '8', '9']

    for i in a:  # Test for each row
        if any([i.count(x) > 1 for x in tmp]):
            print("row issue")
            return False

    # how to test each column, transpose it???



    at = [[a[j][i] for j in range(len(a))] for i in range(len(a[0]))]


    for i in range(9):
        for j in range(9):
            at[j][i] = a[i][j]

    for i in at:  # Test for each col
        if any([i.count(x) > 1 for x in tmp]):
            print("col issue")
            return False

    # now come to the interesting part each 3 by 3
    print(a)
    for i in range(0, 9, 3):
        for j in range(0, 9, 3):
            tmp2 =   [a[i][j],   a[i][j + 1],     a[i][j + 2],
                    a[i + 1][j], a[i + 1][j + 1], a[i + 1][j + 2],
                    a[i + 2][j], a[i + 2][j + 1], a[i + 2][j + 2]]
            print(i,j)
            print(tmp2)
            if any([tmp2.count(x) > 1 for x in tmp]):
                print("sth")
                return False
    return True

a = [["5","3",".",".","7",".",".",".","."],["6",".",".","1","9","5",".",".","."],[".","9","8",".",".",".",".","6","."],["8",".",".",".","6",".",".",".","3"],["4",".",".","8",".","3",".",".","1"],["7",".",".",".","2",".",".",".","6"],[".","6",".",".",".",".","2","8","."],[".",".",".","4","1","9",".",".","5"],[".",".",".",".","8",".",".","7","9"]]

isValidSudoku(a)

matrix = [[1,2],[3,4]]

n = len(matrix)
print(matrix)
for i in range(0, n - 1):
    # print(i)
    for j in range(i + 1, n):
        tmp = matrix[i][j]
        matrix[i][j] = matrix[j][i]
        matrix[j][i] = tmp
print(matrix)

