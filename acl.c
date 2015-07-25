/* -------------------------------------------------------------------------
 *
 * acl.c
 *
 * Copyright (c) 2015 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#if PG_VERSION_NUM >= 90300
#include "access/htup_details.h"
#endif
#include "access/tupmacs.h"
#include "utils/builtins.h"

#include "acl.h"

PG_MODULE_MAGIC;

static char ace_type_chars[] =
{
	'a',	// ACCESS_ALLOWED
	'd'		// ACCESS_DENIED
};

#define ACE_ALL_TYPES_STR		"adi"

static char ace_flag_chars[] =
{
	'0',
	'1',
	'2',
	'3',
	'4',
	'5',
	'6',
	'7',
	'8',
	'9',
	'A',
	'B',
	'C',
	'D',
	'E',
	'F',

	'G',	// RESERVED
	'H',	// RESERVED
	'I',	// RESERVED
	'J',	// RESERVED
	'K',	// RESERVED
	'L',	// RESERVED
	'M',	// RESERVED
	'N',	// RESERVED
	'O',	// RESERVED
	'P',	// RESERVED
	'x',	// INVALID
	'h',	// INHERITED
	'p',	// NO_PROPAGATE_INHERIT
	'c',	// CONTAINER_INHERIT
	'o',	// OBJECT_INHERIT
	'i'		// INHERIT_ONLY
};

#define ACE_ALL_FLAGS_STR		"hpcoi0123456789ABCDEFGHIJKLMNOP"

static char ace_mask_chars[] =
{
	'0',
	'1',
	'2',
	'3',
	'4',
	'5',
	'6',
	'7',
	'8',
	'9',
	'A',
	'B',
	'C',
	'D',
	'E',
	'F',

	'G',	// RESERVED
	'H',	// RESERVED
	'I',	// RESERVED
	'J',	// RESERVED
	'K',	// RESERVED
	'L',	// RESERVED
	'M',	// RESERVED
	'N',	// RESERVED
	'O',	// RESERVED
	'P',	// RESERVED
	'Q',	// RESERVED
	's',	// WRITE_ACL
	'c',	// READ_ACL
	'd',	// DELETE
	'w',	// WRITE
	'r'		// READ
};

#define ACE_ALL_MASKS_STR		"scdwr0123456789ABCDEFGHIJKLMNOPQ"

static int ace_type_inverted[256];
static int ace_flag_inverted[256];
static int ace_mask_inverted[256];

void _PG_init(void);

static void format_mask(StringInfo out, uint32 mask, char mask_chars[]);
static uint32 parse_mask_char(char c);

static void check_acl(const ArrayType *acl);

static void
fill_inverted_map(char map[], int inverted_map[], int len, int first_index)
{
	int			i;

	for (i = 0; i < 256; ++i)
		inverted_map[i] = -1;

	for (i = 0; i < len; ++i)
		inverted_map[(int) map[i]] = i + first_index;
}

void
_PG_init(void)
{
	fill_inverted_map(ace_type_chars, ace_type_inverted, 2, 1);
	fill_inverted_map(ace_flag_chars, ace_flag_inverted, 32, 0);
	fill_inverted_map(ace_mask_chars, ace_mask_inverted, 32, 0);
}

void
parse_acl_entry(const char *s, AclEntryBase *acl_entry_base,
				void *opaque,
				const char *parse_who(const char *s, void *opaque))
{
	uint32		type;
	uint32		flags;
	uint32		mask;

	while (isspace((unsigned char) *s))
		++s;

	if (*s == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing ACE type")));

	type = ace_type_inverted[(int) *s++];
	if (type == -1)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid ACE type: must be one of \"%s\"",
						ACE_ALL_TYPES_STR)));

	while (isspace((unsigned char) *s))
		++s;

	if (*s++ != '/')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing \"/\" sign")));

	if (*s == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing ACE flags")));

	flags = 0;
	for (; *s != '\0' && *s != '/'; ++s)
	{
		int		flag_bit;

		flag_bit = ace_flag_inverted[(int) *s];
		if (flag_bit == -1)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("invalid ACE flag: must be one of \"%s\"",
							ACE_ALL_FLAGS_STR)));

		flags |= 1 << flag_bit;
	}

	while (isspace((unsigned char) *s))
		++s;

	if (*s++ != '/')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing \"/\" sign")));

	while (isspace((unsigned char) *s))
		++s;

	if (*s == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing ACE who")));

	s = parse_who(s, opaque);

	if (*s++ != '=')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing \"=\" sign")));

	while (isspace((unsigned char) *s))
		++s;

	if (*s == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("missing ACE mask")));

	mask = 0;
	for (; *s != '\0'; ++s)
		mask |= parse_mask_char(*s);

	while (isspace((unsigned char) *s))
		++s;

	if (*s != '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("extra garbage at the end of the ACE specification")));

	acl_entry_base->type = type;
	acl_entry_base->flags |= flags;
	acl_entry_base->mask |= mask;
}

void
format_acl_entry(StringInfo out, void *acl_entry,
				 AclEntryBase *acl_entry_base,
				 void (*format_who)(StringInfo out, void *acl_entry))
{
	appendStringInfoChar(out, ace_type_chars[acl_entry_base->type - 1]);

	appendStringInfoChar(out, '/');
	format_mask(out, acl_entry_base->flags, ace_flag_chars);

	appendStringInfoChar(out, '/');
	format_who(out, acl_entry);

	appendStringInfoChar(out, '=');
	format_mask(out, acl_entry_base->mask, ace_mask_chars);
}

uint32
check_access(const ArrayType *acl, int16 typlen, char typalign,
			 AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
			 uint32 mask, intptr_t who,
			 bool (*who_matches)(void *acl_entry, intptr_t who),
			 bool implicit_allow)
{
	uint32		granted = 0;
	int			i;
	char	   *entry;
	int			num;

	check_acl(acl);

	num = ARR_DIMS(acl)[0];
	entry = ARR_DATA_PTR(acl);

	for (i = 0; mask != 0 && i < num; ++i)
	{
		AclEntryBase   *base = extract_acl_entry_base(entry);

		/* There could be more ACE types in the future */
		if (base->type == ACE_ACCESS_ALLOWED ||
			base->type == ACE_ACCESS_DENIED)
		{
			if (!(base->flags & (ACE_INHERIT_ONLY | ACE_INVALID)) &&
				(mask & base->mask) &&
				who_matches(entry, who))
			{
				if (base->type == ACE_ACCESS_ALLOWED)
				{
					granted |= mask & base->mask;
				}

				mask &= ~base->mask;
			}
		}

		if (i != num - 1)
		{
			entry = att_addlength_pointer(entry, typlen, entry);
			entry = (char *) att_align_nominal(entry, typalign);
		}
	}

	if (implicit_allow)
		granted |= mask;

	return granted;
}

text *
check_access_text_mask(const ArrayType *acl, int16 typlen,
					   char typalign,
					   AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
					   text *text_mask, intptr_t who,
					   bool (*who_matches)(void *acl_entry, intptr_t who),
					   bool implicit_allow)
{
	char	   *mask_str;
	int			mask_len;
	uint32		mask;
	int			i;
	uint32		granted;
	StringInfo	out;

	mask_str = VARDATA_ANY(text_mask);
	mask_len = VARSIZE_ANY_EXHDR(text_mask);

	mask = 0;
	for (i = 0; i < mask_len; ++i)
		mask |= parse_mask_char(*mask_str++);

	granted = check_access(acl, typlen, typalign, extract_acl_entry_base,
						   mask, who, who_matches, implicit_allow);

	out = makeStringInfo();
	format_mask(out, granted, ace_mask_chars);

	return cstring_to_text(out->data);
}

void
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

static uint32
parse_mask_char(char c)
{
	int			mask_bit;

	mask_bit = ace_mask_inverted[(int) c];
	if (mask_bit == -1)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid ACE mask: must be one of \"%s\"",
						ACE_ALL_MASKS_STR)));

	return 1 << mask_bit;
}

static void
format_mask(StringInfo out, uint32 mask, char mask_chars[])
{
	int			i;

	for (i = 0; i < 32; ++i)
		if (mask & (1 << i))
			appendStringInfoChar(out, mask_chars[i]);
}

static void
check_acl(const ArrayType *acl)
{
	if (ARR_NDIM(acl) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("ACL arrays must be one-dimensional")));

	if (ARR_HASNULL(acl))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("ACL arrays must not contain null values")));
}
