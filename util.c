/* -------------------------------------------------------------------------
 *
 * util.c
 *
 * Copyright (c) 2015-2023 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "util.h"

static void check_who_array(ArrayType *who_array);

bool
check_access_extract_args(FunctionCallInfo fcinfo, ArrayType **acl,
						  uint32 *mask, ArrayType **who, bool *implicit_allow,
						  bool extract_who, bool has_who_argument)
{
	if (PG_ARGISNULL(0))
		*acl = NULL;
	else
		*acl = PG_GETARG_ARRAYTYPE_P(0);

	if (PG_ARGISNULL(1))
		return false;

	*mask = PG_GETARG_UINT32(1);

	if (has_who_argument && PG_ARGISNULL(2))
		return false;

	if (extract_who)
	{
		*who = PG_GETARG_ARRAYTYPE_P(2);
		check_who_array(*who);
	}

	if (PG_ARGISNULL(has_who_argument ? 3 : 2))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("allow_implicit argument must be not null")));

	*implicit_allow = PG_GETARG_BOOL(3);

	return true;
}

bool
check_access_text_mask_extract_args(FunctionCallInfo fcinfo, ArrayType **acl,
									text **mask, ArrayType **who,
									bool *implicit_allow, bool extract_who,
									bool has_who_argument)
{
	if (PG_ARGISNULL(0))
		*acl = NULL;
	else
		*acl = PG_GETARG_ARRAYTYPE_P(0);

	if (PG_ARGISNULL(1))
		return false;

	*mask = PG_GETARG_TEXT_P(1);

	if (has_who_argument && PG_ARGISNULL(2))
		return false;

	if (extract_who)
	{
		*who = PG_GETARG_ARRAYTYPE_P(2);
		check_who_array(*who);
	}

	if (PG_ARGISNULL(has_who_argument ? 3 : 2))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("allow_implicit argument must be not null")));

	*implicit_allow = PG_GETARG_BOOL(3);

	return true;
}

void
merge_acls_extract_args(FunctionCallInfo fcinfo, ArrayType **parent,
						ArrayType **child, bool *container, bool *deny_first)
{
	if (PG_ARGISNULL(0))
		*parent = NULL;
	else
		*parent = PG_GETARG_ARRAYTYPE_P(0);

	if (PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("ACL must be not null")));

	*child = PG_GETARG_ARRAYTYPE_P(1);

	if (PG_ARGISNULL(2))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("container argument must be not null")));

	*container = PG_GETARG_BOOL(2);

	if (PG_ARGISNULL(3))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("deny_first argument must be not null")));

	*deny_first = PG_GETARG_BOOL(3);
}

static void
check_who_array(ArrayType *who_array)
{
	if (ARR_HASNULL(who_array))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("Who array must not contain null values")));

	if (ARR_NDIM(who_array) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("wrong number of dimensions of who array"),
				 errdetail("Who array must be one dimensional.")));

	if (ARR_NDIM(who_array) > 0 && ARR_LBOUND(who_array)[0] != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("wrong range of who array"),
				 errdetail("Lower bound of who array must be one.")));
}
