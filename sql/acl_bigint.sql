-- ACL format checks
select ''::ace_bigint;
select 'a'::ace_bigint;
select 'q'::ace_bigint;
select 'a*'::ace_bigint;

select 'a/'::ace_bigint;
select 'a/hq'::ace_bigint;
select 'a/h'::ace_bigint;

select 'a/h/'::ace_bigint;

select 'a/h/='::ace_bigint;
select 'a/h/1='::ace_bigint;
select 'a/h/1=d,'::ace_bigint;
select 'a/h/1=dw'::ace_bigint;
select 'a/ihpc/1=wdddw'::ace_bigint;
select 'd/ihpc/1=wdddw'::ace_bigint;
select 'd/ihpc/-9223372036854775808=wdddw'::ace_bigint;
select 'd/ihpc/9223372036854775807=wdddw'::ace_bigint;
select 'a/ihpc/blah"=dw0'::ace_bigint;
select 'd/ihpc/9223372036854775808=wdddw'::ace_bigint;
select 'd/ihpc/922337203685477580800=wdddw'::ace_bigint;

-- check access
select acl_check_access('{d//1=w,d//2=s,a//2=sdw,a//3=0}'::ace_bigint[], 'sd0', '{3, 2}'::bigint[], false);

-- inherit only
select acl_check_access('{d//1=w,d/i/2=s,a//2=sdw,a//3=0}'::ace_bigint[], 'sd0', '{3, 2}'::bigint[], false);
