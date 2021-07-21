def get_nth(a,n):
    aset = set(sorted(a.values()))
    if len(aset) < n or n ==0:
        return 'No {} largest value exsit'.format(n)

    target_val = list(aset)[-n]
    print(target_val)
    alist = [idx for idx, val in a.items() if val == target_val]
    return(sorted(alist)[0])

a = {'BreakingBad':100,'UA':100 ,'GameOfThrones':1292, 'GP':1292,'TMKUC' : 88}
n = 5
get_nth(a,n)
