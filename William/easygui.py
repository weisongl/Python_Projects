from easygui import *
import easygui as eg
from random import random, randrange

name = eg.enterbox(f'What is your name: ', 'Name')
eg.msgbox(f"Hello, {name}!")

msg = f"Hi {name},Which math do you want to do?"
title = "William's math game!"
choices = ["Plus", "Minus", ]
choice = eg.choicebox(msg, title, choices)
eg.msgbox("You chose: " + str(choice), "")

number_of_questions = int(eg.enterbox(f'How many questions do you want to solve ', 'number of questions'))

while number_of_questions > 0:
    number_of_questions -= 1
    a = randrange(1, 11)
    b = randrange(1, 11)
    answer = eg.enterbox(f'What is {a} + {b} ', f' Your {choice} question')

    if choice == 'Plus':
        if answer == str(a + b):
            print(f"Good job,{name}! You're doing awesome and great!!!"
                  f"\nThere're {number_of_questions} questions left")
        else:
            print(f"Sorry,{name}! No the right answer!!!"
                  f"\nThere're {number_of_questions} questions left")
    elif choice == 'Minus':
        if answer == str(a - b):
            print(f"Good job,{name}! You're doing awesome and great!!!"
                  f"\nThere're {number_of_questions} questions left")
        else:
            print(f"Sorry,{name}! No the right answer!!!"
                  f"\nThere're {number_of_questions} questions left")

    print(f"You're doing great {name}, keep up the good work!")