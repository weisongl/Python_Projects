import tkinter as tk
from tkinter import simpledialog
from tkinter import *
from random import random, randrange

class MyDialog(simpledialog.Dialog):
    def body(self, master):
        self.geometry("800x600")
        tk.Label(master, text="Enter your search string text:").grid(row=0)

        self.e1 = tk.Entry(master)
        self.e1.grid(row=0, column=1)
        return self.e1 # initial focus

    def apply(self):
        first = self.e1.get()
        self.result = first



if __name__ == "__main__":
    ROOT = tk.Tk()
    ROOT.withdraw()

    MyDialog(ROOT, "testing")



    # ROOT.mainloop()

    name = simpledialog.askstring(title='name', prompt="What is your name?")
    # print out the name
    print(name)

    # cal = simpledialog.askstring(title='Math', prompt="Do you want to do plus or minus?")
    # print('Ok let\' do some {} calculation'.format(cal))

    number_of_questions = 0

    while number_of_questions > 0:
        number_of_questions -= 1
        a = randrange(1,11)
        b = randrange(1,11)

        # answer = simpledialog.askstring(title='math', prompt=f"what is {a} + {b}")
        # if answer == str(a+b):
        #     print(f"Good job,{name}! You're doing awesome and great!!!"
        #           f"\nThere're {number_of_questions} questions left")
        # else:
        #     print(f"Sorry,{name}! No the right answer!!!"
        #           f"\nThere're {number_of_questions} questions left")

        answer = simpledialog.askstring(title='math', prompt=f"what is {a} - {b}")
        if answer == str(a-b):
            print(f"Good job,{name}! You're doing awesome and great!!!"
                  f"\nThere're {number_of_questions} questions left")
        else:
            print(f"Sorry,{name}! No the right answer!!!"
                  f"\nThere're {number_of_questions} questions left")


    print(f"You're doing great {name}, keep up the good work!")