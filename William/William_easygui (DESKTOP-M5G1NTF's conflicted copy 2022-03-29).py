from easygui import *
import pandas as pd
from random import random, randrange

if __name__ == "__main__":
    name = enterbox(f'What is your name: ', 'Name')
    msgbox(f"Hello, {name}!")

    msg = f"Hi {name},Which math do you want to do?"
    title = "William's math game!"
    choices = ["Plus", "Minus", "Multiplication","Plus and Minus","All!!!!!"]
    choice = choicebox(msg, title, choices)
    Plus_Minus_flag = choice == "Plus and Minus"
    all_choice_flag = choice == "All!!!!!"
    msgbox("You chose: " + str(choice), "")

    number_of_questions = int(enterbox(f'How many questions do you want to solve ', 'number of questions'))
    correct_number = 0
    total_number = number_of_questions.

    while number_of_questions > 0:
        number_of_questions -= 1
        a = randrange(1, 11)
        b = randrange(1, 11)
        # answer = enterbox(f'What is {a} + {b} ', f' Your {choice} question')

        if all_choice_flag:
            choice = choices[:3][randrange(0, 3)]

        if Plus_Minus_flag:
            choice = choices[:2][randrange(0, 2)]

        if choice == 'Plus':
            answer = enterbox(f'What is {a} + {b} ', f' Your {choice} question')
            if answer == str(a + b):
                correct_number += 1
                msgbox(f"Good job,{name}! You're doing awesome and great!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Good job,{name}! You're doing awesome and great!!!"
                      f"\nThere're {number_of_questions} questions left")
            else:
                msgbox(f"Sorry,{name}! No the right answer!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Sorry,{name}! No the right answer!!!"
                      f"\nThere're {number_of_questions} questions left")
        elif choice == 'Minus':
            answer = enterbox(f'What is {a} - {b} ', f' Your {choice} question')
            if answer == str(a - b):
                correct_number += 1
                msgbox(f"Good job,{name}! You're doing awesome and great!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Good job,{name}! You're doing awesome and great!!!"
                      f"\nThere're {number_of_questions} questions left")
            else:
                msgbox(f"Sorry,{name}! No the right answer!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Sorry,{name}! No the right answer!!!"
                      f"\nThere're {number_of_questions} questions left")
        elif choice == "Multiplication":
            a = randrange(1, 5)
            b = randrange(1, 3)
            answer = enterbox(f'What is {a} × {b} ', f' Your {choice} question')
            if answer == str(a * b):
                correct_number += 1
                msgbox(f"Good job,{name}! You're doing awesome and great!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Good job,{name}! You're doing awesome and great!!!"
                      f"\nThere're {number_of_questions} questions left")
            else:
                msgbox(f"Sorry,{name}! No the right answer!!!"
                       f"\nThere're {number_of_questions} questions left")
                print(f"Sorry,{name}! No the right answer!!!"
                      f"\nThere're {number_of_questions} questions left")
    score = "{:.2f}".format(correct_number * 100.0 / total_number)
    msgbox(f"You're doing great {name}, keep up the good work! you got {score} points")
