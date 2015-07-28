/* -------------------------------------------------------------------------
 *
 * acl_int8.c
 *
 * Copyright (c) 2015 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#include "utils/builtins.h"
#include "utils/int8.h"

#include "acl.h"

PG_FUNCTION_INFO_V1(ace_int8_in);
PG_FUNCTION_INFO_V1(ace_int8_out);
PG_FUNCTION_INFO_V1(acl_int8_check_access_text);
PG_FUNCTION_INFO_V1(acl_int8_check_access_int4);

Datum ace_int8_in(PG_FUNCTION_ARGS);
Datum ace_int8_out(PG_FUNCTION_ARGS);
Datum acl_int8_check_access_text(PG_FUNCTION_ARGS);
Datum acl_int8_check_access_int4(PG_FUNCTION_ARGS);

typedef struct AclEntryInt8
{
	AclEntryBase 	base;
	char			who[8];
} AclEntryInt8;

#define ACL_TYPE_ALIGNMENT				'i'
#define ACL_TYPE_LENGTH					sizeof(AclEntryInt8)

#define DatumGetInt8AclEntryP(x)		((AclEntryInt8 *) DatumGetPointer(x))
#define PG_GETARG_BIGINT_ACL_ENTRY_P(x)	DatumGetInt8AclEntryP(PG_GETARG_DATUM(x))
#define PG_RETURN_BIGINT_ACL_ENTRY_P(x)	PG_RETURN_POINTER(x)

static const char *parse_who(const char *s, void *opaque);
static void format_who(StringInfo out, void *acl_entry);

static AclEntryBase *extract_acl_entry_base(void *entry);
static bool who_matches(void *entry, intptr_t who);

Datum
ace_int8_in(PG_FUNCTION_ARGS)
{
	const char	   *s = PG_GETARG_CSTRING(0);
	AclEntryInt8   *entry;

	entry = palloc0(sizeof(AclEntryInt8));

	parse_acl_entry(s, &entry->base, entry->who, parse_who);

	PG_RETURN_BIGINT_ACL_ENTRY_P(entry);
}

Datum
ace_int8_out(PG_FUNCTION_ARGS)
{
	AclEntryInt8   *entry = PG_GETARG_BIGINT_ACL_ENTRY_P(0);
	StringInfo		out;

	out = makeStringInfo();

	format_acl_entry(out, entry->who, &entry->base, format_who);

	PG_RETURN_CSTRING(out->data);
}

Datum
acl_int8_check_access_int4(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl = PG_GETARG_ARRAYTYPE_P(0);
	uint32			mask = PG_GETARG_UINT32(1);
	ArrayType	   *who = PG_GETARG_ARRAYTYPE_P(2);
	bool			implicit_allow = PG_GETARG_BOOL(3);
	uint32			result;

	check_who_array(who);

	result = check_access(acl, ACL_TYPE_LENGTH, ACL_TYPE_ALIGNMENT,
						  extract_acl_entry_base, mask,
						  (intptr_t) who, who_matches,
						  implicit_allow);

	PG_RETURN_UINT32(result);
}

Datum
acl_int8_check_access_text(PG_FUNCTION_ARGS)
{
	ArrayType	   *acl = PG_GETARG_ARRAYTYPE_P(0);
	text		   *mask = PG_GETARG_TEXT_P(1);
	ArrayType	   *who = PG_GETARG_ARRAYTYPE_P(2);
	bool			implicit_allow = PG_GETARG_BOOL(3);
	text		   *result;

	check_who_array(who);

	result = check_access_text_mask(acl, ACL_TYPE_LENGTH,
									ACL_TYPE_ALIGNMENT,
									extract_acl_entry_base, mask,
									(intptr_t) who, who_matches,
									implicit_allow);

	PG_RETURN_TEXT_P(result);
}

static const char *
parse_who(const char *s, void *opaque)
{
	char			str[21];
	int				len = 0;
	int64			who;

	for (; *s != '\0' && (*s == '-' || isdigit((unsigned char) *s)); ++s)
	{
		if (len >= 20)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("int8 too long")));

		str[len++] = *s;
	}

	str[len] = '\0';

	who = DatumGetInt64(DirectFunctionCall1(int8in, CStringGetDatum(str)));
	memcpy(opaque, &who, 8);

	return s;
}

static void
format_who(StringInfo out, void *opaque)
{
	int64 who;

	memcpy(&who, opaque, 8);

	appendStringInfoString(out, DatumGetCString(DirectFunctionCall1(
										int8out, Int64GetDatum(who))));
}

static AclEntryBase *
extract_acl_entry_base(void *entry)
{
	return &((AclEntryInt8 *) entry)->base;
}

static bool
who_matches(void *entry, intptr_t who)
{
	int64			entry_who;
	bool			result = false;
	int				i, num;
	int64		   *ptr;

	memcpy(&entry_who, ((AclEntryInt8 *) entry)->who, 8);

	num = ARR_DIMS((ArrayType *) who)[0];
	ptr = (int64 *) ARR_DATA_PTR((ArrayType *) who);

	for (i = 0; i < num; ++i)
	{
		int64			who_value = *ptr++;

		if (entry_who == who_value)
		{
			result = true;
			break;
		}
	}

	return result;
}
