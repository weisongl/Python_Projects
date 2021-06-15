import sys
import requests
year = 2000
query = 'harry*'

year = 2007
query = '*walk in*'

year=1997
query = 'waterworld'

yr = str(year)
s = query
left_flag = s[0] == '*'
right_flag = s[-1] == '*'
s[:-1]
if left_flag and right_flag:
    s = s[1:]
    s = s[:-1]
elif left_flag:
    s = s[1:]
elif right_flag:
    s = s[:-1]
r = requests.get('http://jsonmock.hackerrank.com/api/movies?Year={}&page=1'.format(yr)).json()
total_page = int(r['total_pages'])

result = []
for j in range(0, total_page + 1):
    r = requests.get('http://jsonmock.hackerrank.com/api/movies?Year={}&page={}'.format(str(year), str(j))).json()
    per = r['per_page']
    for i in range(len(r['data'])):
        if len(r['data'][i]["Title"]) < len(s):
            continue
        # print(r['data'][i]["Title"])
        if left_flag and right_flag and s in r['data'][i]["Title"][1:-1].lower():
            # print()
            result.append([r['data'][i]['imdbID'], r['data'][i]['Title']])
            # print(r['data'][i])
        # elif left_flag and s in r['data'][i]["Title"][1:].lower():
        elif left_flag and s == r['data'][i]["Title"][-len(s):].lower():
            result.append([r['data'][i]['imdbID'], r['data'][i]['Title']])
            # print(r['data'][i])
        # elif right_flag and s in r['data'][i]["Title"][:-1].lower():
        elif right_flag and s == r['data'][i]["Title"][:len(s)].lower():
            result.append([r['data'][i]['imdbID'], r['data'][i]['Title']])
            # print(r['data'][i])
        elif not left_flag and not right_flag and s == r['data'][i]["Title"].lower():
            result.append([r['data'][i]['imdbID'], r['data'][i]['Title']])
            # print(r['data'][i])
var = sys.stdout
output = []
for i in result:
    if i not in output:
        output.append(i)

for i in output:
    var.write(str(i[0]) + " " + str(i[1] + "\n"))