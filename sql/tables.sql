
create table product(
id int IDENTITY(1,1) NOT NULL,
name varchar(20),
description varchar(100),
price decimal(8,3) 
);

create table coupon(
id int IDENTITY(1,1) NOT NULL,
code varchar(20) UNIQUE,
discount decimal(8,3),
exp_date varchar(100) 
);
