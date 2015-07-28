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
  * oid vs int4 vs int8 vs uuid vs text
  * PostgreSQL 9.5 Row-level security integration

Performance benchmarks

  1. PostgreSQL Roles (~ 300 ns/check, 18% overhead)
     2 000 000 records, ~ 20 ACEs in ACL, 100 roles, 10 000 grants
       * Full scan. Count: 1958000, time: 00:00:03.542818
       * ACL scan. Count: 1864000, time: 00:00:04.160114

  2. int4 (~ 400 ns/check, 29% overhead)
     2 000 000 records, ~ 20 ACEs in ACL, 100 int4s, user has 20 int4s
       * Full scan. Count: 1954000, time: 00:00:02.84305
       * ACL scan. Count: 954000, time: 00:00:03.662651

  3. int8 (~ 350 ns/check, 20% overhead)
     2 000 000 records, ~ 20 ACEs in ACL, 100 int8s, user has 20 int8s
       * Full scan. Count: 1954000, time: 00:00:03.482425
       * ACL scan. Count: 954000, time: 00:00:04.176515

  4. UUID (~ 600 ns/check, 36% overhead)
     2 000 000 records, ~ 20 ACEs in ACL, 100 UUIDs, user has 20 UUIDs
       * Full scan. Count: 1920000, time: 00:00:03.504945
       * ACL scan. Count: 968000, time: 00:00:04.757497
