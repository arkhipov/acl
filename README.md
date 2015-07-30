Access Control Lists (ACL) Extension
====================================

[![Build Status](https://travis-ci.org/arkhipov/acl.svg?branch=master)](https://travis-ci.org/arkhipov/acl)

Quick Start
===========

Why do I need this?
-------------------

You need this extension if you want to restrict access to rows in tables based
on an authenticated user.  Access Control List (ACL) has become the de-facto
standard for implementing a security model in modern applications.  Complex
scenarios can be handled by using ACLs without having a complex permission
model at the application level.

This document is not intended to be a tutorial on ACLs and security and
describes the Access Control List Extension only. You can find more information
on ACLs on the sites below.

  1. [Wikipedia: Access Control List](https://en.wikipedia.org/wiki/Access_control_list)
  2. [MSDN: How AccessCheck Works](https://msdn.microsoft.com/en-us/library/windows/desktop/aa446683%28v=vs.85%29.aspx)
  3. [MSDN: ACL Technology Overview](https://msdn.microsoft.com/en-us/library/ms229742%28v=vs.110%29.aspx)
  3. [Network File System (NFS) version 4 Protocol](https://www.ietf.org/rfc/rfc3530.txt)
  4. [POSIX Access Control Lists on Linux](http://users.suse.com/~agruen/acl/linux-acls/online/)

The extension provides you with a number of special types representing ACL
entries (ACEs) and a set of functions that check a user against an ACL.

But wait! There is already the `aclitem` type. What is wrong with it?
---------------------------------------------------------------------

The `aclitem` is an internal type.  Its behaviour may change in a future
release without notice, so do not rely on it unless you like living
dangerously.  Besides, in a typical mid-tier/server environment, applications
rarely have separate database accounts for each user, which means that the
`aclitem` type will do little to help you secure your application.

How do I set it up?
-------------------

The easiest way to install the extension is to to use the
[PGXN client](http://pgxnclient.projects.pgfoundry.org/).

    $ pgxn install acl

But if you stick with the good old Make, you can set up the extension like
this:

    $ make
    $ make install
    $ make installcheck

Once the extension is installed, you can add it to a database.

    $ CREATE EXTENSION acl;

How can I create an ACL?
------------------------

Since an ACL is a simple one-dimensional PostgreSQL array, the easiest way to
create it is from a literal constant.

```SQL
SELECT '{a/i/postgres=rwd, d//user=r, a//=r}'::ace[];
```

ACL can have zero or more access control entries (ACE).  Every ACE has the
following textual representation.

    [type]/[flags]/[who]=[mask]

There are two types of ACEs: allow and deny (`a` and `d` in a textual
representation).  The `type` part is mandatory.

The who part defines for which role this ACE is in effect.  There is a special
identifier "" (empty string) representing everyone.

Mask is a string value that specifies the permissions that are allowed or
denied in an ACE.

For more information on ACLs see ACL Structure section below.

How can I check if the user has the permission to access the data?
------------------------------------------------------------------

Once you created an ACL, you may want to determine if it grants a current or
any particular user a specified set of permissions.  In order to do this, use
one of the following functions.

  * acl_check_access(ace[] acl, text mask, bool implicit_allow)
  * acl_check_access(ace[] acl, int4 mask, bool implicit_allow)
  * acl_check_access(ace[] acl, text mask, oid role, bool implicit_allow)
  * acl_check_access(ace[] acl, int4 mask, oid role, bool implicit_allow)
  * acl_check_access(ace[] acl, text mask, name role, bool implicit_allow)
  * acl_check_access(ace[] acl, int4 mask, name role, bool implicit_allow)

The first two check the PostgreSQL current user against the specified ACL while
the four others take the role to check in its third parameters.

There are two types of `acl_check_` functions which take `text` or `int4` as
the mask.  Production environments should **always** use the latter form as it
is much more efficient.

The functions return the granted permissions (either as a `text` or `int4`,
depending on the type of their mask parameters).  If no permissions are granted,
an empty string is returned.

There is also an additional parameter `implicit_allow` which controls whether
permission is granted if it was not explicitly granted or denied in the ACL.

I need custom permissions. Is it possible?
------------------------------------------

There are 16 custom flags and 16 custom permission (see ACE Structure section
below).  How you use them is up to you.  All the extension functions ignore
custom flags.

Does this work with PostgreSQL 9.5 row-level security?
------------------------------------------------------

Yes!  The Access Control List Extension integrates flawlessly with PostgreSQL
row-level security.  All you need is to add an ACL column to your data table
and define security policies.

```SQL
CREATE TABLE file_system (id int, parent_id int, name text, acl ace[]);

GRANT SELECT, INSERT, UPDATE, DELETE ON file_system TO PUBLIC;

ALTER TABLE file_system ENABLE ROW LEVEL SECURITY;

CREATE POLICY file_system_read_policy ON file_system FOR SELECT TO PUBLIC
USING (acl_check_access(acl, 'r', false) = 'r');

CREATE POLICY file_system_update_policy ON file_system FOR UPDATE TO PUBLIC
USING (acl_check_access(acl, 'w', false) = 'w');

CREATE POLICY file_system_delete_policy ON file_system FOR DELETE TO PUBLIC
USING (acl_check_access(acl, 'd', false) = 'd');

CREATE POLICY file_system_insert_policy ON file_system FOR INSERT TO PUBLIC
WITH CHECK (acl_check_access((SELECT p.acl FROM file_system p WHERE p.id = file_system.parent_id), 'w', false) = 'w');

INSERT INTO file_system(id, parent_id, name, acl)
VALUES (1, NULL, '/', '{a//=r}'),
       (2, 1, '/home', '{a//=rdw}'),
       (3, 1, '/bin', '{a//postgres=rdw}');
```

Then connect as another user and check how it works.

```SQL
SELECT * FROM file_system;
```

```
id | parent_id | name  |    acl
---+-----------+-------+-----------
 1 |           | /     | {a//=r}
 2 |         1 | /home | {a//=dwr}
```

```SQL
INSERT INTO file_system (id, parent_id, name, acl)
VALUES(10, 1, '/test', '{a//=rdw}');
```

    ERROR:  new row violates row level security policy for "file_system"

```SQL
INSERT INTO file_system (id, parent_id, name, acl)
VALUES(10, 2, '/home/test', '{a//=rdw}');
```

    INSERT 0 1

```SQL
DELETE FROM file_system WHERE id = 1;
```

    DELETE 0

```SQL
DELETE FROM file_system WHERE id = 10;
```

    DELETE 1

What if my application does not rely on the PostgreSQL roles system?
--------------------------------------------------------------------

You can still use the Access Control List Extension even if your application
does not rely on the PostgreSQL roles system.  There are three additional ACE
types supported.

  1. ace_int4 (e.g. a/h/1985=rdw, d//-2015=s)
  2. ace_int8 (e.g. a/h/0=w, d/oic/1234567890=AB)
  3. ace_uuid (e.g. a//00001101-0000-1000-8000-00805F9B34FB=r)

And a set of `acl_check_` functions that are slightly different from the ones
you have seen so far.

  * acl_check_access(ace_int4 acl, text mask, int4[] roles, bool implicit_allow)
  * acl_check_access(ace_int4 acl, int4 mask, int4[] roles, bool implicit_allow)
  * acl_check_access(ace_int8 acl, text mask, int8[] roles, bool implicit_allow)
  * acl_check_access(ace_int8 acl, int4 mask, int8[] roles, bool implicit_allow)
  * acl_check_access(ace_uuid acl, text mask, uuid[] roles, bool implicit_allow)
  * acl_check_access(ace_uuid acl, int4 mask, uuid[] roles, bool implicit_allow)

The third parameter of these functions is an array of roles that your
application considers the user has.

How does it impact performance?
-------------------------------

It introduces some overhead in the data reading, depending on the type and
size of the ACLs (see Performance Benchmarks below), averaging 25%.  It is way
faster than any existing mid-tier security solution could offer.

I no longer see role names in ACEs! What happened?
--------------------------------------------------

Sometimes you will see a number sign (#) followed by a number instead of a role
name.

    d/h/#42=w

Or an entry with a special 'x' (INVALID) flag.

    a/ox/=rd

It happens when the OID specified in the ACL entry cannot be resolved to a role
name.  One of the most likely causes is that the role was deleted.  Since ACLs
are usually set on a large number of objects, it would be unwise to try to
remove invalid entries every time a role is being removed from the system, so
these invalid ACEs remain there until you remove them manually.  Another
imporant reason that makes us provide a reasonable textual representation of
every ACE is that PostgreSQL uses them to make backups and restores.

Are there any tutorials on how to use the extension and ACLs in an application?
-------------------------------------------------------------------------------

Unfortunately, no, but feel free to write one :)

Building the extension
======================

To build it, just do this:

    $ make
    $ make install
    $ make installcheck

If you encounter an error such as:

    "Makefile", line 8: Need an operator

You need to use GNU make, which may well be installed on your system as gmake:

    $ gmake
    $ gmake install
    $ gmake installcheck

If you encounter an error such as:

    make: pg_config: Command not found

Be sure that you have pg_config installed and in your path.  If you used a
package management system such as RPM to install PostgreSQL, be sure that the
-devel package is also installed.  If necessary tell the build process where to
find it:

    $ env PG_CONFIG=/path/to/pg_config make && make install && make installcheck

If you encounter an error such as:

    ERROR: must be owner of database regression

You need to run the test suite using a super user, such as the default
"postgres" super user:

    $ make installcheck PGUSER=postgres

Once the extension is installed, you can add it to a database.  Connect to a
database as a super user and do this:

    $ CREATE EXTENSION acl;

ACE structure
=============

ACE textual representation
--------------------------

    [type]/[flags]/[who]=[mask]

Examples

  * `a/ihpc/acl_test1=wd`
  * `d/ox/acl_test1=s`
  * `a//"acl test2"=dw0`
  * `a//"test""blah"=AB1`
  * `d//=`

ACE types
---------

  Type  | Description
  ----- | -------------------------------------------
  ALLOW | Explicitly grants the access to the object.
  DENY  | Explicitly denies the access to the object.


ACE flags
---------

  Flag                 | Mask           | Description
  -------------------- | -------------- | ------------------------------------------------------------------------
  INHERIT_ONLY         | 0x80000000 (i) | Indicates that this ACE does not apply to the current object.
  OBJECT_INHERIT       | 0x40000000 (o) | Indicates that child objects will inherit this ACE.
  CONTAINER_INHERIT    | 0x20000000 (c) | Indicates that child containers will inherit this ACE.
  NO_PROPAGATE_INHERIT | 0x10000000 (p) | Indicates that child containers will not propagate this ACE any further.
  INHERITED            | 0x08000000 (h) | Indicates that this ACE was inherited from another container.
  INVALID              | 0x04000000 (x) | Indicates that this ACE must not used while checking permissions.
                       |                | Flags from 0x02000000 to 0x00010000 are reserved for the future use.
                       | 0x00008000 (F) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00004000 (E) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00002000 (D) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00001000 (C) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000800 (B) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000400 (A) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000200 (9) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000100 (8) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000080 (7) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000040 (6) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000020 (5) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000010 (4) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000008 (3) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000004 (2) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000002 (1) | Flags from 0x00008000 to 0x00000001 are application-specific.
                       | 0x00000001 (0) | Flags from 0x00008000 to 0x00000001 are application-specific.

ACE permissions
---------------

  Permission | Mask           | Description
  ---------- | -------------- | --------------------------------------------------------------------------
  READ       | 0x80000000 (r) | Permission to read the object.
  WRITE      | 0x40000000 (w) | Permission to write the object.
  DELETE     | 0x20000000 (d) | Permission to delete the object.
  READ_ACL   | 0x10000000 (c) | Permission to read the ACL of the object.
  WRITE_ACL  | 0x08000000 (s) | Permission to modify the ACL of the object.
             |                | Permissions from 0x04000000 to 0x00010000 are reserved for the future use.
             | 0x00008000 (F) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00004000 (E) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00002000 (D) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00001000 (C) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000800 (B) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000400 (A) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000200 (9) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000100 (8) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000080 (7) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000040 (6) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000020 (5) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000010 (4) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000008 (3) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000004 (2) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000002 (1) | Permissions from 0x00008000 to 0x00000001 are application-specific.
             | 0x00000001 (0) | Permissions from 0x00008000 to 0x00000001 are application-specific.

ACE who
-------

There is a special identifier "" (empty string) representing everyone.

Performance Benchmarks
======================

Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz (fam: 06, model: 3a, stepping: 09)

Linux 3.13.0-generic Ubuntu SMP x86_64, PostgreSQL 9.4.4

~ 20 entries in each ACL

  ACE type | Checks per sec | Read rate, records per sec | Read overhead
  -------- | -------------- | -------------------------- | -------------
  OID      |    3.2 million |               0.48 million |           18%
  int4     |    2.4 million |               0.55 million |           29%
  int8     |    2.9 million |               0.48 million |           20%
  UUID     |    1.6 million |               0.42 million |           36%

Notes
=====

Access Control List Extension is distributed under the terms of BSD 2-clause
license. See LICENSE or http://www.opensource.org/licenses/bsd-license.php for
more details.
