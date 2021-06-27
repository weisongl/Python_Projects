print("Welcome to Python Pizza Deliveries!")
size = input("What size pizza do you want? S, M, or L ")
add_pepperoni = input("Do you want pepperoni? Y or N ")
extra_cheese = input("Do you want extra cheese? Y or N ")

price = 0
pepperoni = 0 if add_pepperoni == "N" else 1


if size == 'S':
    price += 15 + pepperoni*2
elif size == 'M':
    price += 20 + pepperoni*3
else:
    price += 25 + pepperoni*3

print(price)

price += 1 if extra_cheese == "Y" else 0