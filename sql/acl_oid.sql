-- set up users
create user acl_test1;
create user "acl test2";
create user """acl=""s,/a//acl_test1";
create user acl_temporary_user;

-- ACL format checks
select ''::ace;
select 'a'::ace;
select 'q'::ace;
select 'a*'::ace;

select 'a/'::ace;
select 'a/hq'::ace;
select 'a/h'::ace;

select 'a/h/'::ace;

select 'a/h/='::ace;
select 'a/h/acl_test1='::ace;
select 'a/h/acl_test1=d,'::ace;
select 'a/h/acl_test1=dw'::ace;
select 'a/ihpc/acl_test1=wdddw'::ace;
select 'd/ihpc/acl_test1=wdddw'::ace;
select 'a/ihpc/"acl test2"=dw0'::ace;

-- invalid role
select 'a//blah=d'::ace;

-- deleted role
create table acl_test (ace ace);
insert into acl_test (ace) values ('a//acl_temporary_user=s');
drop user acl_temporary_user;
select ace::text ~ '#' from acl_test;

-- invalid acl
select (ace::text::ace::text) ~ '#' from acl_test;

-- current user
set role 'acl_test1';
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0');
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29))::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0');
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29))::bit(32);
reset role;

set role """acl=""s,/a//acl_test1";
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c');
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28))::bit(32);
reset role;

-- name
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0', 'acl_test1');
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1')::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0', 'acl_test1');
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1')::bit(32);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c', '"acl="s,/a//acl_test1');
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28), '"acl="s,/a//acl_test1')::bit(32);

-- oid
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'));
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'))::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'));
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'))::bit(32);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c', (select oid from pg_roles where rolname = '"acl="s,/a//acl_test1'));
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28), (select oid from pg_roles where rolname = '"acl="s,/a//acl_test1'))::bit(32);

-- inherit only
select acl_check_access('{d/i/=s,a//acl_test1=sdw}'::ace[], 'sd0', 'acl_test1');
select acl_check_access('{d/i/=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1')::bit(32);

-- clean up
drop user acl_test1;
drop user "acl test2";
drop user """acl=""s,/a//acl_test1";
