digits = '123'
hash_map = {"1": "", "2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv",
            "9": "wxyz"}
digits = dict(enumerate(digits))
print(digits)
print(digits.get(0, "1"))
a = hash_map[digits.get(0, "1")]
b = hash_map[digits.get(1, "1")]
c = hash_map[digits.get(2, "1")]
d = hash_map[digits.get(3, "1")]

digits.get(4)


