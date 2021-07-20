import datetime

m,d,y = map(int, input().split())
datetime.date(y,m,d).weekday()
weekdays = ['MONDAY','TUESDAY','WEDNESDAY','THURSDAY','FRIDAY','SATURDAY','SUNDAY']

print(weekdays[datetime.date(y,m,d).weekday()])
