A = [1,1,2,3]
B = [i for i in set(A) if i > 0]

def solution(A):
    # write your code in Python 3.6
    B = [i for i in set(A) if i > 0]
    print(B)
    if not B:
        return 1
    elif len(B) == 1:
        if B[0] == 1:
            return 2
        else:
            return 1
    else:
        for idx, val in enumerate(B):
            print(idx+1, val)
            if idx + 1 != val:
                return idx + 1

solution(A)