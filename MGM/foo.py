import re

input = "9^R1234|10^R12323|9^R55EW|Z|Z^5623|U^YGFS|UND^RTS12|9^R2Z|9^R2ZTRS|10^R2 ZTRS|10^UND|11^RTZFRSERS|11^RTFRSERS|11^ZTFRSERS|11^ZT FR"
restrict = ["9^R1*", "9^R2.", "10^R2.", "9^MXYZ123", "9^R3", "9^R123", "9^R123", "UND/UND", "11^RTZ-ERS", "11^ZT*-ERS"]

input = input.replace('^', '_').split('|')
output = []
for i in range(len(restrict)):
    restrict[i] = restrict[i].replace('^', '_')

for i in input:
    for j in restrict:
        if bool(re.match(j, i)):
            print(i)
