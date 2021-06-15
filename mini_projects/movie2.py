import sys
import requests

year = 2000
query = 'harry*'

year = 2007
query = '*walk in*'

# year=1997
# query = 'waterworld'

s = query
yr = year
Lflag = s[0] == '*'
Rflag = s[-1] == '*'
s[1:]
s[:-1]

if Lflag and Rflag:
    s = s[1:]
    s = s[:-1]
elif Lflag:
    s = s[1:]
elif Rflag:
    s = s[:-1]
s

import requests

r = requests.get('http://jsonmock.hackerrank.com/api/movies?Year={}&page=1'.format(yr)).json()
total_pages = r['total_pages']
output = []
for i in range(0, total_pages + 1):
    r = requests.get('http://jsonmock.hackerrank.com/api/movies?Year={}&page={}'.format(yr, i)).json()
    per = r['per_page']
    mlist = r['data']
    for j in mlist:
        title = j['Title']
        imdbID = j['imdbID']
        # print(title)
        if Rflag and Lflag and s in title[1:-1].lower():
            # print(title)
            output.append([imdbID, title])
        elif Rflag and not Lflag and s == title[:-len(s)].lower():
            output.append([imdbID, title])
        elif not Rflag and Lflag and s == title[:len(s)].lower():
            output.append([imdbID, title])
        elif not Rflag and not Lflag and s == title.lower():
            output.append([imdbID, title])


realoutput = []

for i in output:
    if i not in realoutput:
        realoutput.append(i)

for i in realoutput:
    print(*i)