select id, max(upload_photo_time),max(tag_time),max(add_time),max(post_time)
(
select id, case when action = 'upload' then time as upload_photo_time,
       case when action = 'tag' then time as tag_time,
       case when action = 'add message' then time as add_time,
       case when action = 'post' then time as post_time
from photo) as tmp
group by 1






---loanbalance
select p.*, sum(p.amout) over(partition by account order by p.paymentdate)
from payment.p


--add cache
SET GLOBAL query_cache_size=1024*1024*16;
SET GLOBAL query_cache_type=1;
SET PROFILING=1;
SELECT name FROM firms WHERE id=727;
SELECT name FROM firms WHERE id=727;
SHOW PROFILES;







--DAU
--calculated retention users. Calculated active user is with the with clause
with monthly_activity as (
select DISTINCT MONTH,
  user_id
  from events
  where event = 'login'
) -- active user for each month

select this_month.month,
count(this_month.user_id)

from monthly_activity as this_month
join monthly_activity as previou_month
on this_month.user_id = previous_month.user_id
and this_month.month = monthadd(previous_month.month, 1)
group by 1 order by 1;
--calculated new users.
select month, count(user_id)
from
(select user_id,date_trunc(month, min(time)) as month
from events where event = 'login'
group by user_id) as tmp
group by 1 order by 1 DESC

--churned users
-- how to calculate churn users
with monthly_activity as (
select DISTINCT MONTH,
  user_id
  from events
  where event = 'login'
)
select this_month.month,count(previous_month.user_id)

from month_activity previous_month
left join month_activity this_month
on previous_month.user_id = this_month.user_id
and previous_month.month = monthadd(this_month.month,-1)
WHERE this_month.user_id is null
group by 1
order by 1 desc
--returned user
-- how to calculated return users.
-- active user this month - new user - retention.
-- get the time when user first logon in
--exclusive all reeion user.
with month_activity as (
select DISTINCT date_trunc(month,date) as MONTH, user_id
  from events
  where event = 'login'
),
newuser as (
select DISTINCT user_id, date_trunc(month, min(date)) as first_month.
  from events
  where event = login
)
select
this_month.month, count(this_month.user_id)

from month_activity this_month
left join month_activity previous_month
on this_month.user_id = prevous_month.user_id
and this_month.month = add_month(previous_month.month,1)
where prevous_month.user_id is null -- select user that active in this month but not last month.
and (this_month.user_id, this_month.month) not in ( select * from newuser)
group by 1
order by 1 DESC



