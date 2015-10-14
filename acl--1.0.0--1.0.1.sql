/* acl/acl--1.0.0--1.0.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION acl UPDATE TO '1.0.1'" to load this file.\quit

ALTER FUNCTION acl_check_access(ace[], text, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace[], int4, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace[], text, oid, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace[], int4, oid, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace[], text, name, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace[], int4, name, bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_uuid[], text, uuid[], bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_uuid[], int4, uuid[], bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_int4[], text, int4[], bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_int4[], int4, int4[], bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_int8[], text, int8[], bool) CALLED ON NULL INPUT;

ALTER FUNCTION acl_check_access(ace_int8[], int4, int8[], bool) CALLED ON NULL INPUT;
