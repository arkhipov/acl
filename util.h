/* -------------------------------------------------------------------------
 *
 * util.h
 *
 * Copyright (c) 2015-2023 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include "postgres.h"
#include "fmgr.h"

#include "utils/array.h"

bool check_access_extract_args(FunctionCallInfo fcinfo, ArrayType **acl,
							   uint32 *mask, ArrayType **who,
							   bool *implicit_allow, bool extract_who,
							   bool has_who_argument);
bool check_access_text_mask_extract_args(FunctionCallInfo fcinfo,
										 ArrayType **acl, text **mask,
										 ArrayType **who, bool *implicit_allow,
										 bool extract_who,
										 bool has_who_argument);

void merge_acls_extract_args(FunctionCallInfo fcinfo, ArrayType **parent,
							 ArrayType **child, bool *container,
							 bool *deny_first);

#endif
