if __name__ == "__main__":
    print("Welcome to the tip calculator:")

    ######################## enter a total bill ##############################
    total_bill = input("What's the total bill?")
    while not total_bill.isnumeric():
        total_bill = input("The input you entered was not a number, please enter again"
                           "\nWhat's the total bill?")
    total_bill = float(total_bill)

    ######################## enter number of people  ##############################
    number_of_people = input("How many people to split the bill?")
    while not number_of_people.isnumeric():
        number_of_people = input("The input you entered was not a number, please enter again"
                                 "\nHow many people to split the bill?")
    number_of_people = float(number_of_people)

    ######################## enter a percentage tip ##############################
    tip_percentage = input("What percentage tip would you like to give?")
    while not tip_percentage.isnumeric():
        tip_percentage = input("The input you entered was not a number, please enter again"
                               "\nWhat percentage tip would you like to give?")
    tip_percentage = float(tip_percentage)

    pay= total_bill*(1+tip_percentage/100)/number_of_people
    print(f"Each person should pay ${pay}")