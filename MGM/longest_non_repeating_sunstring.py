class Solution:
    def lengthOfLongestSubstring(s ):
        n = len(s)

        for i in range(n, 0, -1):  # length of the substring
            for j in range(
                    n - i + 1):  # starting place of substring. test: if i = 1 and n = 3, j could be any 0 1 2.   n-1+1=3 so range(3) would be 0 1 2. if i =n then j could only be at 0
                # print(set(s[j:j+i]),s[j:j+i])
                if len(set(s[j:j + i])) == len(s[j:j + i]):
                    return i

len('')