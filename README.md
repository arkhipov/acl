Access Control Lists (ACL) Extension
====================================

[![Build Status](https://travis-ci.org/arkhipov/acl.svg?branch=master)](https://travis-ci.org/arkhipov/acl)

Roadmap
-------

  * audit
  * cache role checks
  * send/recv
  * operators for indices
  * acl creation functions (inheritance)

TODO Documentation
------------------

Design notes
  * invalid aces
  * oid vs bigint vs uuid vs text
  * PostgreSQL 9.5 Row-level security integration

Performance benchmarks

  1. PostgreSQL Roles (~ 600 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 roles, 10 000 grants
       * Full scan. Count: 10000000, time: 00:00:31.049074
       * ACL scan. Count: 9579999, time: 00:00:36.91982

  2. UUID (~ 2000 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 UUIDs, user has 20 UUIDs
       * Full scan. Count: 10000000, time: 00:00:34.563646
       * ACL scan. Count: 4699999, time: 00:00:53.950049

  3. Bigint ( ~ 2900 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 bigints, user has 20 bigints
       * Full scan. Count: 10000000, time: 00:00:41.962131
       * ACL scan. Count: 2519999, time: 00:01:09.405431
