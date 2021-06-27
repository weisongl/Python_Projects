import os
os. getcwd()

os. chdir("C:\\Users\\yzhou\\Dropbox\\Python\\mini_projects")

f = open("input.txt", "r")
f.read()


newf=""
with open('input.txt','r') as f:
    for line in f:
        newf+="["+ line.strip()+"]\n"
    newf.replace(" ",",")
    f.close()
newf = newf.replace(" ",",")
with open('output.txt','w') as f:
    f.write(newf)
    f.close()
newf

import webbrowser
webbrowser.open("output.txt")