-- ACL format checks
select ''::ace_uuid;
select 'a'::ace_uuid;
select 'q'::ace_uuid;
select 'a*'::ace_uuid;

select 'a/'::ace_uuid;
select 'a/hq'::ace_uuid;
select 'a/h'::ace_uuid;

select 'a/h/'::ace_uuid;

select 'a/h/='::ace_uuid;
select 'a/h/00000000-0000-0000-0000-000000000001='::ace_uuid;
select 'a/h/00000000-0000-0000-0000-000000000001=d,'::ace_uuid;
select 'a/h/00000000-0000-0000-0000-000000000001=dw'::ace_uuid;
select 'a/ihpc/00000000-0000-0000-0000-000000000001=wdddw'::ace_uuid;
select 'd/ihpc/00000000-0000-0000-0000-000000000001=wdddw'::ace_uuid;
select 'd/ihpc/a0000000-ffff-b000-c000-d00000000001=wdddw'::ace_uuid;
select 'a/ihpc/blah"=dw0'::ace_uuid;
select 'd/ihpc/a0000000-ffff-b000-c000-d000000000010000=wdddw'::ace_uuid;

-- check access
select acl_check_access('{d//00000000-0000-0000-0000-000000000001=w,d//00000000-0000-0000-0000-000000000002=s,a//00000000-0000-0000-0000-000000000002=sdw,a//00000000-0000-0000-0000-000000000003=0}'::ace_uuid[], 'sd0', '{00000000-0000-0000-0000-000000000003, 00000000-0000-0000-0000-000000000002}'::uuid[]);

-- inherit only
select acl_check_access('{d//00000000-0000-0000-0000-000000000001=w,d/i/00000000-0000-0000-0000-000000000002=s,a//00000000-0000-0000-0000-000000000002=sdw,a//00000000-0000-0000-0000-000000000003=0}'::ace_uuid[], 'sd0', '{00000000-0000-0000-0000-000000000003, 00000000-0000-0000-0000-000000000002}'::uuid[]);
