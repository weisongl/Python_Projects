def list_difference(A,B):
    return list(set(A).difference(set(B)))

A = "Hello world"
B = "Hello Bob"
A = set(A.split())
B = set(B.split())

A^B