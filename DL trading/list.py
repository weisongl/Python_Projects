n = int(input())
student_marks = {}
for _ in range(n):
    name, *line = input().split()
    scores = list(map(float, line))
    student_marks[name] = scores
query_name = input()
print(sum(student_marks[query_name]) / len(student_marks[query_name]))

a, *b = 'Krisha 67 68 69'.split(' ')
a
b

"%.2f".format(56/3)