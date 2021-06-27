from collections import Counter
magazine = ['ive' ,'got', 'a' ,'lovely' ,'bunch' ,'of' ,'coconuts']
note = ['ive', 'got', 'some' ,'coconuts']
a = Counter(magazine)
b = Counter(note)


s1 = "abc"
s2 = "tec"

a = Counter(s1)
b = Counter(s2)

if (a&b):
    print('wow')