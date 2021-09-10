details = { 'iPhone':  [0, 1,0,1,0,1,0],
            'Android': [1, 0,0,0,0,0,1],
            'Web':     [0, 0,1,0,0,0,0]}
for sub in details:
    print(sub)

rollup = {}
rollup['overall'] = []
rollup['Mobile'] = []

for i,j,k in zip(details['iPhone'],details['Android'],details['Web']):
    total = 1 if i+j+k > 0 else 0
    mobile = 1 if i + j > 0 else 0
    rollup['overall'].append(total)
    rollup['Mobile'].append(mobile)

print(rollup)