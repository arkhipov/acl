create temporary table uuids (n bigint not null primary key, uuid uuid);
create temporary table acl_data (n bigint not null primary key, acl ace_uuid[]);

select setseed(0);

insert into uuids (n, uuid)
select g1, ('00000000-0000-0000-0000-0000000000' || lpad(g1::text, 2, '0'))::uuid
from generate_series(0, 99) g1;

insert into acl_data (n, acl)
select g1, t.acl
from generate_series(0, $unique_aces - 1) g1
  cross join lateral (
    select array_agg((t.type || '//' || u.uuid || '=' || a.rights)::ace_uuid) as acl
    from generate_series(1, (random() * $ace_count * (g1 + 1))::integer % $ace_count) g2
      cross join lateral (select * from uuids where n = (random() * g1 * g2)::bigint % 100) u
      cross join lateral (select t as type from unnest(string_to_array('ad', null)) t order by random() * g1 * g2 limit 1) t
      cross join lateral (select string_agg(t, '') as rights from (select t from unnest(string_to_array('scdwr0123456789ABCDEFGHIJKLMNOPQ', null)) t order by random() * g1 * g2 limit (random() * 10 + 1)::integer) t) a
  ) t;

vacuum full analyze acl_data;

create temporary view acl_test as
select g, (select d.acl from acl_data d where d.n = g % $unique_aces)
from generate_series(1, $count) g;

do $$
declare
  v_role oid;
  v_count bigint;
  v_time1 timestamptz;
  v_time2 timestamptz;
begin
  v_time1 = clock_timestamp();
  select count(*) into v_count from acl_test where acl is not null;
  v_time2 = clock_timestamp();
  raise notice 'Full scan. Count: %, time: %', v_count, v_time2 - v_time1;

  v_time1 = clock_timestamp();
  select count(*) into v_count from acl_test where acl_check_access(acl, '011010000000000000000000'::bit(32)::int4, (select array_agg(uuid) from uuids where n < 20), true) = '011010000000000000000000'::bit(32)::int4;
  v_time2 = clock_timestamp();
  raise notice 'ACL scan. Count: %, time: %', v_count, v_time2 - v_time1;
end;
$$ language plpgsql;
