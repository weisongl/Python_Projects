import tkinter as tk
from tkinter import simpledialog
from random import random, randrange

if __name__ == "__main__":
    ROOT = tk.Tk()
    ROOT.withdraw()

    name = simpledialog.askstring(title='name', prompt="What is your name?")

    # print out the name
    print(name)

    number_of_questions = 5

    while number_of_questions > 0:
        number_of_questions -= 1
        a = randrange(1,11)
        b = randrange(1,11)

        answer = simpledialog.askstring(title='math', prompt=f"what is {a} + {b}")
        if answer == str(a+b):
            print(f"Good job,{name}! You're doing awesome and great!!!"
                  f"\nThere're {number_of_questions} questions left")

    print(f"You're doing great {name}, keep up the good work!")