/* -------------------------------------------------------------------------
 *
 * acl_oid.c
 *
 * Copyright (c) 2015 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "utils/uuid.h"

#include "acl.h"

PG_FUNCTION_INFO_V1(ace_uuid_in);
PG_FUNCTION_INFO_V1(ace_uuid_out);
PG_FUNCTION_INFO_V1(acl_uuid_check_access_text);
PG_FUNCTION_INFO_V1(acl_uuid_check_access_int4);

Datum ace_uuid_in(PG_FUNCTION_ARGS);
Datum ace_uuid_out(PG_FUNCTION_ARGS);
Datum acl_uuid_check_access_text(PG_FUNCTION_ARGS);
Datum acl_uuid_check_access_int4(PG_FUNCTION_ARGS);

typedef struct AclEntryUUID
{
	AclEntryBase 	base;
	char			who[UUID_LEN];
} AclEntryUUID;

#define ACL_TYPE_ALIGNMENT				'i'
#define ACL_TYPE_LENGTH					sizeof(AclEntryUUID)

#define DatumGetUUIDAclEntryP(x)		((AclEntryUUID *) DatumGetPointer(x))
#define PG_GETARG_UUID_ACL_ENTRY_P(x)	DatumGetUUIDAclEntryP(PG_GETARG_DATUM(x))
#define PG_RETURN_UUID_ACL_ENTRY_P(x)	PG_RETURN_POINTER(x)

static const char *parse_who(const char *s, void *opaque);
static void format_who(StringInfo out, void *acl_entry);

static AclEntryBase *extract_acl_entry_base(void *entry);
static bool who_matches(void *entry, intptr_t who);
static void check_who_array(ArrayType *who_array);

Datum
ace_uuid_in(PG_FUNCTION_ARGS)
{
	const char	   *s = PG_GETARG_CSTRING(0);
	AclEntryUUID   *entry;

	entry = palloc0(sizeof(AclEntryUUID));

	parse_acl_entry(s, &entry->base, &entry->who, parse_who);

	PG_RETURN_UUID_ACL_ENTRY_P(entry);
}

Datum
ace_uuid_out(PG_FUNCTION_ARGS)
{
	AclEntryUUID   *entry = PG_GETARG_UUID_ACL_ENTRY_P(0);
	StringInfo		out;

	out = makeStringInfo();

	format_acl_entry(out, &entry->who, &entry->base, format_who);

	PG_RETURN_CSTRING(out->data);
}

Datum
acl_uuid_check_access_int4(PG_FUNCTION_ARGS)
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
acl_uuid_check_access_text(PG_FUNCTION_ARGS)
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
	char			str[37];
	int				len = 0;
	pg_uuid_t	   *uuid;

	for (; *s != '\0' && (*s == '-' || isalnum((unsigned char) *s)); ++s)
	{
		if (len >= 36)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("UUID too long"),
					 errdetail("UUID must be exactly 36 characters.")));

		str[len++] = *s;
	}

	str[len] = '\0';

	uuid = (pg_uuid_t *) DirectFunctionCall1(uuid_in, CStringGetDatum(str));

	memcpy(opaque, uuid, UUID_LEN);

	return s;
}

static void
format_who(StringInfo out, void *opaque)
{
	appendStringInfoString(out, DatumGetCString(DirectFunctionCall1(
										uuid_out, UUIDPGetDatum(opaque))));
}

static AclEntryBase *
extract_acl_entry_base(void *entry)
{
	return &((AclEntryUUID *) entry)->base;
}

static bool
who_matches(void *entry, intptr_t who)
{
	pg_uuid_t	   *entry_who;
	ArrayIterator	array_iterator;
	Datum			value;
	bool			isnull;
	bool			result = false;

	entry_who = (pg_uuid_t *) ((AclEntryUUID *) entry)->who;
	array_iterator = array_create_iterator((ArrayType *) who, 0);

	while (array_iterate(array_iterator, &value, &isnull))
	{
		pg_uuid_t	   *uuid;

		Assert(!isnull);

		uuid = DatumGetUUIDP(value);

		if (memcmp(entry_who, uuid, UUID_LEN) == 0)
		{
			result = true;
			break;
		}
	}

	array_free_iterator(array_iterator);

	return result;
}

static void
check_who_array(ArrayType *who_array)
{
	if (ARR_HASNULL(who_array))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("Who array must not contain null values")));


	if (ARR_NDIM(who_array) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("wrong number of dimensions of who array"),
				 errdetail("Who array must be one dimensional.")));

	if (ARR_LBOUND(who_array)[0] != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("wrong range of who array"),
				 errdetail("Lower bound of who array must be one.")));
}

