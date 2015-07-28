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

  1. PostgreSQL Roles (~ 2000 ns/check)
     2 000 000 records, ~ 20 ACEs in ACL, 100 roles, 10 000 grants
       * Full scan. Count: 2000000, time: 00:00:00.35447
       * ACL scan. Count: 1952000, time: 00:00:04.368787

  2. int4 (~ 1800 ns/check)
     2 000 000 records, ~ 20 ACEs in ACL, 100 int4s, user has 20 int4s
       * Full scan. Count: 2000000, time: 00:00:00.352337
       * ACL scan. Count: 946000, time: 00:00:03.883238

  3. int8 (~ 2000 ns/check)
     2 000 000 records, ~ 20 ACEs in ACL, 100 int8s, user has 20 int8s
       * Full scan. Count: 2000000, time: 00:00:00.356625
       * ACL scan. Count: 946000, time: 00:00:04.453037

  4. UUID (~ 2300 ns/check)
     2 000 000 records, ~ 20 ACEs in ACL, 100 UUIDs, user has 20 UUIDs
       * Full scan. Count: 2000000, time: 00:00:00.355792
       * ACL scan. Count: 972000, time: 00:00:04.947118
