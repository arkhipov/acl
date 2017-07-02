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
select coalesce(acl_check_access('{}'::ace[], 'sd0', false), 'NULL');
select acl_check_access('{}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), false)::bit(32);
select coalesce(acl_check_access(null::ace[], 'sd0', false), 'NULL');
select acl_check_access(null::ace[], (1 << 0) | (1 << 27) | (1 << 29), false)::bit(32);

select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0', false);
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), false)::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0', false);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), false)::bit(32);
reset role;

set role """acl=""s,/a//acl_test1";
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c', false);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28), false)::bit(32);
reset role;

-- name
select coalesce(acl_check_access('{}'::ace[], 'sd0', 'acl_test1', false), 'NULL');
select acl_check_access('{}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1', false)::bit(32);
select coalesce(acl_check_access(null::ace[], 'sd0', 'acl_test1', false), 'NULL');
select acl_check_access(null::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1', false)::bit(32);
select coalesce(acl_check_access('{}'::ace[], 'sd0', null, false), 'NULL');
select acl_check_access('{}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), null, false)::bit(32);

select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0', 'acl_test1', false);
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1', false)::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0', 'acl_test1', false);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1', false)::bit(32);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c', '"acl="s,/a//acl_test1', false);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28), '"acl="s,/a//acl_test1', false)::bit(32);

-- oid
select coalesce(acl_check_access('{}'::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'), false), 'NULL');
select acl_check_access('{}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'), false)::bit(32);
select coalesce(acl_check_access(null::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'), false), 'NULL');
select acl_check_access(null::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'), false)::bit(32);
select coalesce(acl_check_access('{}'::ace[], 'sd0', null, false), 'NULL');
select acl_check_access('{}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), null, false)::bit(32);

select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'), false);
select acl_check_access('{d//=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'), false)::bit(32);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], 'sd0', (select oid from pg_roles where rolname = 'acl_test1'), false);
select acl_check_access('{a//acl_test1=s0,d//=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), (select oid from pg_roles where rolname = 'acl_test1'), false)::bit(32);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], 'c', (select oid from pg_roles where rolname = '"acl="s,/a//acl_test1'), false);
select acl_check_access('{d/hpc/acl_test1=dw0,a//\"\"\"acl=\"\"s\,/a//acl_test1\"=c}'::ace[], (1 << 28), (select oid from pg_roles where rolname = '"acl="s,/a//acl_test1'), false)::bit(32);

-- inherit only
select acl_check_access('{d/i/=s,a//acl_test1=sdw}'::ace[], 'sd0', 'acl_test1', false);
select acl_check_access('{d/i/=s,a//acl_test1=sdw}'::ace[], (1 << 0) | (1 << 27) | (1 << 29), 'acl_test1', false)::bit(32);

-- merge
select acl_merge(null::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);
select acl_merge(null::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, true);
select acl_merge(null::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);
select acl_merge(null::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, true);

-- inheritance

-- container

-- no flags -> not inherited
select acl_merge('{a//acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- inherit only -> not inherited
select acl_merge('{a/i/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- object inherit -> inherit only + object inherit
select acl_merge('{a/o/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- object inherit + inherit only -> inherit only + object inherit
select acl_merge('{a/oi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- object inherit + no propagate inherit -> no inheritance
select acl_merge('{a/op/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- object inherit + no propagate inherit + inherit only -> no inheritance
select acl_merge('{a/opi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

--container inherit -> container inherit
select acl_merge('{a/c/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

--container inherit + inherit only -> container inherit
select acl_merge('{a/ci/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + no propagate inherit -> no flags
select acl_merge('{a/cp/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + no propagate inherit + inherit only -> no flags
select acl_merge('{a/cpi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + object inherit -> container inherit + object inherit
select acl_merge('{a/co/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + object inherit + inherit only -> container inherit + object inherit
select acl_merge('{a/coi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + object inherit + no propagate inherit -> no flags
select acl_merge('{a/cop/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- container inherit + object inherit + no propagate inherit + inherit only -> no flags
select acl_merge('{a/copi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], true, false);

-- object

-- no flags -> not inherited
select acl_merge('{a//acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- inherit only -> not inherited
select acl_merge('{a/i/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- object inherit -> no flags
select acl_merge('{a/o/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- object inherit + inherit only -> no flags
select acl_merge('{a/oi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- object inherit + no propagate inherit -> no flags
select acl_merge('{a/op/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- object inherit + no propagate inherit + inherit only -> no flags
select acl_merge('{a/opi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

--container inherit -> not inherited
select acl_merge('{a/c/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

--container inherit + inherit only -> not inherited
select acl_merge('{a/ci/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + no propagate inherit -> not inherited
select acl_merge('{a/cp/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + no propagate inherit + inherit only -> not inherited
select acl_merge('{a/cpi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + object inherit -> no flags
select acl_merge('{a/co/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + object inherit + inherit only -> no flags
select acl_merge('{a/coi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + object inherit + no propagate inherit -> no flags
select acl_merge('{a/cop/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- container inherit + object inherit + no propagate inherit + inherit only -> no flags
select acl_merge('{a/copi/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- skip inherited
select acl_merge('{a/h/acl_test1=d}'::ace[], '{a//=0,d//=1,a//=23,d//=4}'::ace[], false, false);

-- clean up
drop user acl_test1;
drop user "acl test2";
drop user """acl=""s,/a//acl_test1";
