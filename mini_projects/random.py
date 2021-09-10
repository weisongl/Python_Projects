from random import randint

rock = '''
    _______
---'   ____)
      (_____)
      (_____)
      (____)
---.__(___)
'''

paper = '''
    _______
---'   ____)____
          ______)
          _______)
         _______)
---.__________)
'''

scissors = '''
    _______
---'   ____)____
          ______)
       __________)
      (____)
---.__(___)
'''

allchoice = [rock,paper,scissors]


your_choice = int(input('Which one you would pick? 0 for rock, 1 for paper and 2 for scissors:' ))

print('Your choice is : ', allchoice[your_choice])

computer_choice = randint(0,2)
print('Computer choice is : ', allchoice[computer_choice])

if your_choice == computer_choice:
    print('You tied with Computer')
elif your_choice - computer_choice == 1 or your_choice - computer_choice == -2:
    print('You win')
else:
    print('You lose')



