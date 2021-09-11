from easygui import *
from random import random, randrange

if __name__ == "__main__":
    name = enterbox(f'What is your name: ', 'Name')
    msgbox(f"Hello, {name}!")

    msg = f"Hi {name},Which math do you want to do?"
    title = "William's math game!"
    choices = ["Plus", "Minus", ]
    choice = choicebox(msg, title, choices)
    msgbox("You chose: " + str(choice), "")

    number_of_questions = int(enterbox(f'How many questions do you want to solve ', 'number of questions'))

    while number_of_questions > 0:
        number_of_questions -= 1
        a = randrange(1, 11)
        b = randrange(1, 11)
        # answer = enterbox(f'What is {a} + {b} ', f' Your {choice} question')

        if choice == 'Plus':
            answer = enterbox(f'What is {a} + {b} ', f' Your {choice} question')
            if answer == str(a + b):
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
                msgbox(f"Good job,{name}! You're doing awesome and great!!!"
                      f"\nThere're {number_of_questions} questions left")
                print(f"Good job,{name}! You're doing awesome and great!!!"
                      f"\nThere're {number_of_questions} questions left")
            else:
                msgbox(f"Sorry,{name}! No the right answer!!!"
                      f"\nThere're {number_of_questions} questions left")
                print(f"Sorry,{name}! No the right answer!!!"
                      f"\nThere're {number_of_questions} questions left")

    msgbox(f"You're doing great {name}, keep up the good work!")
