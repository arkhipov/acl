-- ACL format checks
select ''::ace_int8;
select 'a'::ace_int8;
select 'q'::ace_int8;
select 'a*'::ace_int8;

select 'a/'::ace_int8;
select 'a/hq'::ace_int8;
select 'a/h'::ace_int8;

select 'a/h/'::ace_int8;

select 'a/h/='::ace_int8;
select 'a/h/1='::ace_int8;
select 'a/h/1=d,'::ace_int8;
select 'a/h/1=dw'::ace_int8;
select 'a/ihpc/1=wdddw'::ace_int8;
select 'd/ihpc/1=wdddw'::ace_int8;
select 'd/ihpc/-9223372036854775808=wdddw'::ace_int8;
select 'd/ihpc/9223372036854775807=wdddw'::ace_int8;
select 'a/ihpc/blah"=dw0'::ace_int8;
select 'd/ihpc/9223372036854775808=wdddw'::ace_int8;
select 'd/ihpc/922337203685477580800=wdddw'::ace_int8;

-- check access
select acl_check_access('{d//1=w,d//2=s,a//2=sdw,a//3=0}'::ace_int8[], 'sd0', '{3, 2}'::int8[], false);

-- inherit only
select acl_check_access('{d//1=w,d/i/2=s,a//2=sdw,a//3=0}'::ace_int8[], 'sd0', '{3, 2}'::int8[], false);
