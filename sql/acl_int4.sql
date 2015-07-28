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
