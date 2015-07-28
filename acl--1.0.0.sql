/* acl/acl--1.0.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION acl" to load this file.\quit

-- Oid-based ACE
CREATE FUNCTION ace_in(cstring)
RETURNS ace
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION ace_out(ace)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE TYPE ace (
	INTERNALLENGTH = 16,
	INPUT = ace_in,
	OUTPUT = ace_out
);

COMMENT ON TYPE ace IS 'access control list entry';

CREATE FUNCTION acl_check_access(ace[], text, bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_check_access_text_current_user'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], text, bool) IS 'determine if an ACL grants a specified set of permissions to the current user';

CREATE FUNCTION acl_check_access(ace[], int4, bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_check_access_int4_current_user'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], int4, bool) IS 'determine if an ACL grants a specified set of permissions to the current user';

CREATE FUNCTION acl_check_access(ace[], text, oid, bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_check_access_text_oid'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], text, oid, bool) IS 'determine if an ACL grants a specified set of permissions to the role identified by oid';

CREATE FUNCTION acl_check_access(ace[], int4, oid, bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_check_access_int4_oid'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], int4, oid, bool) IS 'determine if an ACL grants a specified set of permissions to the role identified by oid';

CREATE FUNCTION acl_check_access(ace[], text, name, bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_check_access_text_name'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], text, name, bool) IS 'determine if an ACL grants a specified set of permissions to the role identified by name';

CREATE FUNCTION acl_check_access(ace[], int4, name, bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_check_access_int4_name'
LANGUAGE C STRICT STABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace[], int4, name, bool) IS 'determine if an ACL grants a specified set of permissions to the role identified by name';

-- UUID-based ACE
CREATE FUNCTION ace_uuid_in(cstring)
RETURNS ace_uuid
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION ace_uuid_out(ace_uuid)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE TYPE ace_uuid (
	INTERNALLENGTH = 28,
	INPUT = ace_uuid_in,
	OUTPUT = ace_uuid_out
);

COMMENT ON TYPE ace_uuid IS 'access control list entry (UUID-based)';

CREATE FUNCTION acl_check_access(ace_uuid[], text, uuid[], bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_uuid_check_access_text'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_uuid[], text, uuid[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by UUIDs';

CREATE FUNCTION acl_check_access(ace_uuid[], int4, uuid[], bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_uuid_check_access_int4'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_uuid[], int4, uuid[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by UUIDs';

-- int4-based ACE
CREATE FUNCTION ace_int4_in(cstring)
RETURNS ace_int4
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION ace_int4_out(ace_int4)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE TYPE ace_int4 (
	INTERNALLENGTH = 16,
	INPUT = ace_int4_in,
	OUTPUT = ace_int4_out
);

COMMENT ON TYPE ace_int4 IS 'access control list entry (int4-based)';

CREATE FUNCTION acl_check_access(ace_int4[], text, int4[], bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_int4_check_access_text'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_int4[], text, int4[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by a set of int4s';

CREATE FUNCTION acl_check_access(ace_int4[], int4, int4[], bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_int4_check_access_int4'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_int4[], int4, int4[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by a set of int4s';

-- int8-based ACE
CREATE FUNCTION ace_int8_in(cstring)
RETURNS ace_int8
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE FUNCTION ace_int8_out(ace_int8)
RETURNS cstring
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE;

CREATE TYPE ace_int8 (
	INTERNALLENGTH = 20,
	INPUT = ace_int8_in,
	OUTPUT = ace_int8_out
);

COMMENT ON TYPE ace_int8 IS 'access control list entry (int8-based)';

CREATE FUNCTION acl_check_access(ace_int8[], text, int8[], bool)
RETURNS text
AS 'MODULE_PATHNAME', 'acl_int8_check_access_text'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_int8[], text, int8[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by a set of int8s';

CREATE FUNCTION acl_check_access(ace_int8[], int4, int8[], bool)
RETURNS int4
AS 'MODULE_PATHNAME', 'acl_int8_check_access_int4'
LANGUAGE C STRICT IMMUTABLE LEAKPROOF;

COMMENT ON FUNCTION acl_check_access(ace_int8[], int4, int8[], bool) IS 'determine if an ACL grants a specified set of permissions to the principal identified by a set of int8s';
