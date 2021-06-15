# n,m = map(int,input().split())
#
# c = list(map(int, input().split()))

n = 2
c = [1,2]


n_perms = [1]+[0]*n
for coin in c:
    for i in range(coin,n+1):
        n_perms[i] += n_perms[i-coin]

print(n_perms)
