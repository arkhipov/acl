/* -------------------------------------------------------------------------
 *
 * acl_oid.c
 *
 * Copyright (c) 2015-2023 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#include "miscadmin.h"
#if PG_VERSION_NUM >= 90300
#include "access/htup_details.h"
#endif
#include "access/tupmacs.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include "utils/syscache.h"

#include "acl.h"
#include "util.h"

PGDLLEXPORT Datum ace_in(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum ace_out(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_text_current_user(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_int4_current_user(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_text_oid(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_int4_oid(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_text_name(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_check_access_int4_name(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_merge(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(ace_in);
PG_FUNCTION_INFO_V1(ace_out);
PG_FUNCTION_INFO_V1(acl_check_access_text_current_user);
PG_FUNCTION_INFO_V1(acl_check_access_int4_current_user);
PG_FUNCTION_INFO_V1(acl_check_access_text_oid);
PG_FUNCTION_INFO_V1(acl_check_access_int4_oid);
PG_FUNCTION_INFO_V1(acl_check_access_text_name);
PG_FUNCTION_INFO_V1(acl_check_access_int4_name);
PG_FUNCTION_INFO_V1(acl_merge);

typedef struct AclEntryOid
{
	AclEntryBase 	base;
	Oid				who;
} AclEntryOid;

#define ACL_TYPE_ALIGNMENT			'i'
#define ACL_TYPE_LENGTH				sizeof(AclEntryOid)

#define PUBLIC_OID					0

#define DatumGetAclEntryP(x)		((AclEntryOid *) DatumGetPointer(x))
#define PG_GETARG_ACL_ENTRY_P(x)	DatumGetAclEntryP(PG_GETARG_DATUM(x))
#define PG_RETURN_ACL_ENTRY_P(x)	PG_RETURN_POINTER(x)

static const char *parse_who(const char *s, void *opaque);
static void format_who(StringInfo out, intptr_t opaque);

static AclEntryBase *extract_acl_entry_base(void *entry);
static bool who_matches(void *entry, intptr_t who);

static Oid get_role_oid(const char *name, bool missing_ok);

Datum
ace_in(PG_FUNCTION_ARGS)
{
	const char	   *s = PG_GETARG_CSTRING(0);
	AclEntryOid	   *entry;

	entry = palloc0(sizeof(AclEntryOid));

	parse_acl_entry(s, &entry->base, entry, parse_who);

	PG_RETURN_ACL_ENTRY_P(entry);
}

Datum
ace_out(PG_FUNCTION_ARGS)
{
	AclEntryOid	   *entry = PG_GETARG_ACL_ENTRY_P(0);
	StringInfo		out;

	out = makeStringInfo();

	format_acl_entry(out, (intptr_t) entry, &entry->base, format_who);

	PG_RETURN_CSTRING(out->data);
}

Datum
acl_check_access_int4_current_user(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	uint32			mask;
	bool			implicit_allow;
	Oid				who;

	if (!check_access_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
								   false, false))
		PG_RETURN_NULL();

	who = GetUserId();

	PG_RETURN_UINT32(check_access(acl, ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
								  extract_acl_entry_base, mask,
								  (intptr_t) who, who_matches,
								  implicit_allow));
}

Datum
acl_check_access_text_current_user(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	text		   *mask;
	bool			implicit_allow;
	Oid				who;

	if (!check_access_text_mask_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
											 false, false))
		PG_RETURN_NULL();

	who = GetUserId();

	PG_RETURN_TEXT_P(check_access_text_mask(acl, ACL_TYPE_LENGTH,
											ACL_TYPE_ALIGNMENT,
											extract_acl_entry_base, mask,
											(intptr_t) who, who_matches,
											implicit_allow));
}

Datum
acl_check_access_int4_oid(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	uint32			mask;
	Oid				who;
	bool			implicit_allow;

	if (!check_access_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
								   false, true))
		PG_RETURN_NULL();

	if (PG_ARGISNULL(2))
		PG_RETURN_NULL();

	who = PG_GETARG_OID(2);

	PG_RETURN_UINT32(check_access(acl, ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
								  extract_acl_entry_base, mask,
								  (intptr_t) who, who_matches,
								  implicit_allow));
}

Datum
acl_check_access_text_oid(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	text		   *mask;
	Oid				who;
	bool			implicit_allow;

	if (!check_access_text_mask_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
											 false, true))
		PG_RETURN_NULL();

	if (PG_ARGISNULL(2))
		PG_RETURN_NULL();

	who = PG_GETARG_OID(2);

	PG_RETURN_TEXT_P(check_access_text_mask(acl, ACL_TYPE_LENGTH,
											ACL_TYPE_ALIGNMENT,
											extract_acl_entry_base, mask,
											(intptr_t) who, who_matches,
											implicit_allow));
}

Datum
acl_check_access_int4_name(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	uint32			mask;
	Name			rolename;
	bool			implicit_allow;
	Oid				who;

	if (!check_access_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
								   false, true))
		PG_RETURN_NULL();

	if (PG_ARGISNULL(2))
		PG_RETURN_NULL();

	rolename = PG_GETARG_NAME(2);
	who = get_role_oid(NameStr(*rolename), false);

	PG_RETURN_UINT32(check_access(acl, ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
								  extract_acl_entry_base, mask,
								  (intptr_t) who, who_matches,
								  implicit_allow));
}

Datum
acl_check_access_text_name(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	text		   *mask;
	Name			rolename;
	bool			implicit_allow;
	Oid				who;

	if (!check_access_text_mask_extract_args(fcinfo, &acl, &mask, NULL, &implicit_allow,
											 false, true))
		PG_RETURN_NULL();

	if (PG_ARGISNULL(2))
		PG_RETURN_NULL();

	rolename = PG_GETARG_NAME(2);
	who = get_role_oid(NameStr(*rolename), false);

	PG_RETURN_TEXT_P(check_access_text_mask(acl, ACL_TYPE_LENGTH,
											ACL_TYPE_ALIGNMENT,
											extract_acl_entry_base, mask,
											(intptr_t) who, who_matches,
											implicit_allow));
}

Datum
acl_merge(PG_FUNCTION_ARGS)
{
	ArrayType	   *parent;
	ArrayType	   *child;
	bool			container;
	bool			deny_first;

	merge_acls_extract_args(fcinfo, &parent, &child, &container, &deny_first);

	PG_RETURN_ARRAYTYPE_P(merge_acls(parent, child,
									 ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
									 extract_acl_entry_base,
									 container, deny_first));
}

static const char *
parse_who(const char *s, void *opaque)
{
	char			name[NAMEDATALEN];
	int				len = 0;
	Oid				oid;
	AclEntryOid	   *acl_entry = (AclEntryOid *) opaque;

	if (*s == '#')
	{
		for (++s; *s != '\0' && isalnum((unsigned char) *s); ++s)
		{
			name[len++] = *s;

			if (len >= 9)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid ACE who")));
		}

		name[len] = '\0';

		oid = DatumGetObjectId(DirectFunctionCall1(oidin,
											  CStringGetDatum(name)));

		acl_entry->base.flags |= ACE_INVALID;
	}
	else
	{
		bool		in_quotes = false;

		for (;
			 *s != '\0' &&
			 (isalnum((unsigned char) *s) ||
			  *s == '_' ||
			  *s == '"' ||
			  in_quotes);
			 ++s)
		{
			if (*s == '"')
			{
				if (*(s + 1) != '"')
				{
					in_quotes = !in_quotes;
					continue;
				}

				++s;
			}

			if (len >= NAMEDATALEN - 1)
				ereport(ERROR,
						(errcode(ERRCODE_NAME_TOO_LONG),
						 errmsg("identifier too long"),
						 errdetail("Identifier must be less than %d characters.",
								   NAMEDATALEN)));

			name[len++] = *s;
		}

		if (len == 0)
		{
			oid = PUBLIC_OID;
		}
		else
		{
			name[len] = '\0';
			oid = get_role_oid(name, true);

			if (!OidIsValid(oid))
				acl_entry->base.flags |= ACE_INVALID;
		}
	}

	acl_entry->who = oid;

	return s;
}

static void
format_who(StringInfo out, intptr_t opaque)
{
	HeapTuple		htup;
	AclEntryOid	   *entry = (AclEntryOid *) opaque;

	if (entry->who == PUBLIC_OID)
		return;

	htup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(entry->who));
	if (!HeapTupleIsValid(htup))
	{
		appendStringInfo(out, "#%d", entry->who);
	}
	else
	{
		char   *name = NameStr(((Form_pg_authid) GETSTRUCT(htup))->rolname);
		char   *s;
		bool	safe = true;

		for (s = name; *s; ++s)
		{
			if (!isalnum((unsigned char) *s) && *s != '_')
			{
				safe = false;
				break;
			}
		}

		if (!safe)
			appendStringInfoChar(out, '"');

		for (s = name; *s; ++s)
		{
			if (*s == '"')
				appendStringInfoChar(out, '"');

			appendStringInfoChar(out, *s);
		}

		if (!safe)
			appendStringInfoChar(out, '"');

		ReleaseSysCache(htup);
	}
}

static AclEntryBase *
extract_acl_entry_base(void *entry)
{
	return &((AclEntryOid *) entry)->base;
}

static bool
who_matches(void *entry, intptr_t who)
{
	Oid			entry_who = ((AclEntryOid *) entry)->who;

	return entry_who == PUBLIC_OID || entry_who == (Oid) who;
}

static
Oid get_role_oid(const char *name, bool missing_ok)
{
	Oid			oid;

	oid = GetSysCacheOid1(AUTHNAME, CStringGetDatum(name));
	if (!missing_ok && !OidIsValid(oid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("role \"%s\" does not exist", name)));

	return oid;
}
