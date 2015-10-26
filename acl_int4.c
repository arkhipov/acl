/* -------------------------------------------------------------------------
 *
 * acl_int4.c
 *
 * Copyright (c) 2015 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#include "utils/builtins.h"

#include "acl.h"
#include "util.h"

PGDLLEXPORT Datum ace_int4_in(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum ace_int4_out(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_int4_check_access_text(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_int4_check_access_int4(PG_FUNCTION_ARGS);
PGDLLEXPORT Datum acl_int4_merge(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(ace_int4_in);
PG_FUNCTION_INFO_V1(ace_int4_out);
PG_FUNCTION_INFO_V1(acl_int4_check_access_text);
PG_FUNCTION_INFO_V1(acl_int4_check_access_int4);
PG_FUNCTION_INFO_V1(acl_int4_merge);

typedef struct AclEntryInt4
{
	AclEntryBase 	base;
	int32			who;
} AclEntryInt4;

#define ACL_TYPE_ALIGNMENT				'i'
#define ACL_TYPE_LENGTH					sizeof(AclEntryInt4)

#define DatumGetInt4AclEntryP(x)		((AclEntryInt4 *) DatumGetPointer(x))
#define PG_GETARG_BIGINT_ACL_ENTRY_P(x)	DatumGetInt4AclEntryP(PG_GETARG_DATUM(x))
#define PG_RETURN_BIGINT_ACL_ENTRY_P(x)	PG_RETURN_POINTER(x)

static const char *parse_who(const char *s, void *opaque);
static void format_who(StringInfo out, intptr_t acl_entry);

static AclEntryBase *extract_acl_entry_base(void *entry);
static bool who_matches(void *entry, intptr_t who);

Datum
ace_int4_in(PG_FUNCTION_ARGS)
{
	const char	   *s = PG_GETARG_CSTRING(0);
	AclEntryInt4   *entry;

	entry = palloc0(sizeof(AclEntryInt4));

	parse_acl_entry(s, &entry->base, &entry->who, parse_who);

	PG_RETURN_BIGINT_ACL_ENTRY_P(entry);
}

Datum
ace_int4_out(PG_FUNCTION_ARGS)
{
	AclEntryInt4   *entry = PG_GETARG_BIGINT_ACL_ENTRY_P(0);
	StringInfo		out;

	out = makeStringInfo();

	format_acl_entry(out, entry->who, &entry->base, format_who);

	PG_RETURN_CSTRING(out->data);
}

Datum
acl_int4_check_access_int4(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	uint32			mask;
	ArrayType	   *who;
	bool			implicit_allow;
	uint32			result;

	if (!check_access_extract_args(fcinfo, &acl, &mask, &who, &implicit_allow,
								   true, true))
		PG_RETURN_NULL();

	result = check_access(acl, ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
						  extract_acl_entry_base, mask,
						  (intptr_t) who, who_matches,
						  implicit_allow);

	PG_RETURN_UINT32(result);
}

Datum
acl_int4_check_access_text(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl;
	text		   *mask;
	ArrayType	   *who;
	bool			implicit_allow;
	text		   *result;

	if (!check_access_text_mask_extract_args(fcinfo, &acl, &mask, &who,
											 &implicit_allow, true, true))
		PG_RETURN_NULL();

	result = check_access_text_mask(acl, ACL_TYPE_LENGTH,
									ACL_TYPE_ALIGNMENT,
									extract_acl_entry_base, mask,
									(intptr_t) who, who_matches,
									implicit_allow);

	PG_RETURN_TEXT_P(result);
}

Datum
acl_int4_merge(PG_FUNCTION_ARGS)
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
	char			str[12];
	int				len = 0;

	for (; *s != '\0' && (*s == '-' || isdigit((unsigned char) *s)); ++s)
	{
		if (len >= 11)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("int4 too long")));

		str[len++] = *s;
	}

	str[len] = '\0';

	*((int32 *) opaque) = DatumGetInt32(DirectFunctionCall1(
											int4in, CStringGetDatum(str)));

	return s;
}

static void
format_who(StringInfo out, intptr_t opaque)
{
	appendStringInfoString(out, DatumGetCString(DirectFunctionCall1(
										int4out, Int32GetDatum(opaque))));
}

static AclEntryBase *
extract_acl_entry_base(void *entry)
{
	return &((AclEntryInt4 *) entry)->base;
}

static bool
who_matches(void *entry, intptr_t who)
{
	int32			entry_who;
	bool			result = false;
	int				i, num;
	int32		   *ptr;

	entry_who = ((AclEntryInt4 *) entry)->who;

	num = ArrayGetNItems(ARR_NDIM((ArrayType *) who),
						 ARR_DIMS((ArrayType *) who));
	ptr = (int32 *) ARR_DATA_PTR((ArrayType *) who);

	for (i = 0; i < num; ++i)
	{
		int32			who_value = *ptr++;

		if (entry_who == who_value)
		{
			result = true;
			break;
		}
	}

	return result;
}
