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
where Name = 'Samony'

