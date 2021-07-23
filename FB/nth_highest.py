def get_nth(a,n):
    if n == 0 or len(set(a.values())) < n:
        return '{}th largest value doesn\'t exist'.format(n)

    arr = list(set(sorted(a.values())))
    nth = arr[-n]
    return [idx for idx, val in a.items() if val == nth][0]

a = {'BreakingBad':100,'UA':100 ,'GameOfThrones':1292, 'GP':1292,'TMKUC' : 88}
n = 1
get_nth(a,n)
