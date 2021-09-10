s = '()(()[]{}))('
a = list(s)
a
def valid_p(s):
    a = list(s)
    p_right = [idx for idx, val in enumerate(a) if val == '(']
    p_left = [idx for idx, val in enumerate(a) if val == ')']
    print(p_right,p_left)
    if len(p_right) != len(p_left):
        return False
    else:
        for i,j in zip(p_right,p_left):
            if i>j:
                return False
    return True
valid_p(s)


