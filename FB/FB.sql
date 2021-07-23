select S.name
from Salesperson as S
join Orders as O on S.ID = O.salesperson_id
where O.cust_id not in (
    select ID from Customer
    where name = 'Samsonic'
    )
;
select S.name
from Salesperson as S
join Orders as O on S.ID = O.salesperson_id
group by S.name
having count(O.Number) > 1;

select name, age
from Salesperson
where salary >= 100000;


select S.name
from Salesperson as S
join Orders as O on S.ID = O.salesperson_id
group by S.name
having sum(Amount)  > 1400
;

select O.order_date
from Orders as O join Customer as C
on O.cust_id = C.id
where Name = 'Samony';

--X with top 5 Y (抱歉X和Y记不清了）, order by Y in descending order. Having 即可解决，记得将结果乘以100得到百分数。

select x ,y
  from      (
           select x, y, row_number() over (partition by x order by y DESC ) as row_number
      from table1
       ) as a
where  row_number <= 5







