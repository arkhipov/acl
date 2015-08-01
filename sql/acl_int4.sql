-- ACL format checks
select ''::ace_int4;
select 'a'::ace_int4;
select 'q'::ace_int4;
select 'a*'::ace_int4;

select 'a/'::ace_int4;
select 'a/hq'::ace_int4;
select 'a/h'::ace_int4;

select 'a/h/'::ace_int4;

select 'a/h/='::ace_int4;
select 'a/h/1='::ace_int4;
select 'a/h/1=d,'::ace_int4;
select 'a/h/1=dw'::ace_int4;
select 'a/ihpc/1=wdddw'::ace_int4;
select 'd/ihpc/1=wdddw'::ace_int4;
select 'd/ihpc/-2147483648=wdddw'::ace_int4;
select 'd/ihpc/2147483647=wdddw'::ace_int4;
select 'a/ihpc/blah"=dw0'::ace_int4;
select 'd/ihpc/21474836480=wdddw'::ace_int4;
select 'd/ihpc/214748364800=wdddw'::ace_int4;

-- check access
select acl_check_access('{d//1=w,d//2=s,a//2=sdw,a//3=0}'::ace_int4[], 'sd0', '{3, 2}'::int4[], false);

-- inherit only
select acl_check_access('{d//1=w,d/i/2=s,a//2=sdw,a//3=0}'::ace_int4[], 'sd0', '{3, 2}'::int4[], false);

-- merge
select acl_merge(null::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);
select acl_merge(null::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, true);
select acl_merge(null::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);
select acl_merge(null::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, true);

-- inheritance

-- container

-- no flags -> not inherited
select acl_merge('{a//1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- inherit only -> not inherited
select acl_merge('{a/i/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- object inherit -> inherit only + object inherit
select acl_merge('{a/o/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- object inherit + no propagate inherit -> no inheritance
select acl_merge('{a/op/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

--container inherit -> container inherit
select acl_merge('{a/c/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- container inherit + no propagate inherit -> no flags
select acl_merge('{a/cp/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- container inherit + object inherit -> container inherit + object inherit + inherit only
select acl_merge('{a/co/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- container inherit + object inherit + no propagate inherit -> no flags
select acl_merge('{a/cop/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], true, false);

-- object

-- no flags -> not inherited
select acl_merge('{a//1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- inherit only -> not inherited
select acl_merge('{a/i/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- object inherit -> no flags
select acl_merge('{a/o/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- object inherit + no propagate inherit -> no flags
select acl_merge('{a/op/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

--container inherit -> not inherited
select acl_merge('{a/c/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- container inherit + no propagate inherit -> not inherited
select acl_merge('{a/cp/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- container inherit + object inherit -> no flags
select acl_merge('{a/co/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- container inherit + object inherit + no propagate inherit -> no flags
select acl_merge('{a/cop/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);

-- skip inherited
select acl_merge('{a/h/1=d}'::ace_int4[], '{a//0=0,d//0=1,a//0=23,d//0=4}'::ace_int4[], false, false);
