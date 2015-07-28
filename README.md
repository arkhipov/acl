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
  * oid vs int8 vs uuid vs text
  * PostgreSQL 9.5 Row-level security integration

Performance benchmarks

  1. PostgreSQL Roles (~ 900 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 roles, 10 000 grants
       * Full scan. Count: 10000000, time: 00:00:29.072561
       * ACL scan. Count: 9579999, time: 00:00:37.779871

  2. UUID (~ 800 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 UUIDs, user has 20 UUIDs
       * Full scan. Count: 10000000, time: 00:00:26.843014
       * ACL scan. Count: 7509999, time: 00:00:34.510175

  3. int8 ( ~ 800 ns/check)
     10 000 000 records, ~ 50 ACEs in ACL, 100 int8, user has 20 int8
       * Full scan. Count: 10000000, time: 00:00:37.472098
       * ACL scan. Count: 2519999, time: 00:00:45.005206
