import smtplib
import datetime as dt
import random
import os

# print("Current Working Directory " , os.getcwd())
# path = f'{os.getcwd()}\BirthdayWish'
# os.chdir(path)
# os.getcwd()

now = dt.datetime.now()
weekday = now.weekday()

my_email = "williamlikestv@gmail.com"
password = "kandianshi"



if weekday == 4:
    with open(f'{os.getcwd()}\quotes.txt') as quote_file:
        all_quotes = quote_file.readlines()
        quote = random.choice(all_quotes)

    print(quote)
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        connection.sendmail(from_addr=my_email,
                            to_addrs=my_email,
                            msg="Subject:Hello\n\n{}".format(quote))



# my_email = "williamlikestv@gmail.com"
# password = "kandianshi"
# with smtplib.SMTP("smtp.gmail.com") as connection:
#     connection.starttls()
#     connection.login(user=my_email,password=password)
#     connection.sendmail(from_addr=my_email,
#                         to_addrs=my_email,
#                         msg="Subject:Hello\n\nThis is the body of my email.")
#
# import datetime as dt
# now = dt.datetime.now()
# print(now)
# DOW= now.weekday()
# DOW
#
# year = now.year
# month = now.month
# day = now.day
#
# DOB = dt.datetime(year=1989,month=6,day=12,hour=4)
# DOB
#
#
#
