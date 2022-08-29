from easygui import *
import pandas as pd
from random import random, randrange

if __name__ == "__main__":
    rows_of_questions = 3
    df = pd.DataFrame(columns=["Plus" , "Minus", "Multiplication","Division"])
    # msg = f"Hi William, what level of difficulty you want?"
    # title = "William's math game!"
    # choices = ["easy", "medium", "hard"]
    # difficulty = choicebox(msg, title, choices)
    difficulty = "hard"

    x = ""
    y = ""
    z = ""
    k = ""

    while rows_of_questions > 0:
        rows_of_questions -= 1
        #  for plus column
        if difficulty == 'easy':
            a = randrange(1, 11)
            b = randrange(1, 11)
        elif difficulty == 'medium':
            a = randrange(5, 16)
            b = randrange(1, 11)
        elif difficulty == 'hard':
            a = randrange(5, 16)
            b = randrange(5, 16)
        x = f'{a} + {b} =      '

        # for minus column
        if difficulty == 'easy':
            a = randrange(1, 11)
            b = randrange(1, 11)
        elif difficulty == 'medium':
            a = randrange(5, 16)
            b = randrange(1, 11)
        elif difficulty == 'hard':
            a = randrange(5, 16)
            b = randrange(5, 16)
        y = f'{a} - {b} =      '

        # for multiplication
        if difficulty =='easy':
            a = randrange(1, 5)
            b = randrange(1, 3)
        elif difficulty == 'mediumn':
            a = randrange(1, 8)
            b = randrange(1, 5)
        elif difficulty == 'hard':
            a = randrange(1, 8)
            b = randrange(1, 8)
        z = f'{a} * {b} =      '

        # for division
        if difficulty == 'easy':
            a = randrange(2, 3)
            b = randrange(2, 4)
        elif difficulty == 'medium':
            a = randrange(2, 4)
            b = randrange(2, 4)
        elif difficulty == 'hard':
            a = randrange(2, 5)
            b = randrange(2, 4)

        k = f'{a*b} / {b} =      '
        df.loc[len(df)] = [x, y, z, k]
        print([x, y, z, k])

    df.to_csv("math.csv",index=False)
