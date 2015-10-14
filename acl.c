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

static char * copy_acl_entries(char *src, char *dest, int nitems, int typlen,
					char typalign, int *ncopied,
					bool (*filter)(AclEntryBase *entry),
					void (*modify_entry)(AclEntryBase *src, AclEntryBase *dest),
					AclEntryBase * (*extract_acl_entry_base)(void *acl_entry));

static bool filter_not_inherited(AclEntryBase *entry);
static bool filter_access_denied(AclEntryBase *entry);
static bool filter_access_allowed(AclEntryBase *entry);
static bool filter_inherited_container(AclEntryBase *entry);
static bool filter_inherited_object(AclEntryBase *entry);
static void modify_inherited_container(AclEntryBase *src, AclEntryBase *dest);
static void modify_inherited_object(AclEntryBase *src, AclEntryBase *dest);

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
format_acl_entry(StringInfo out, intptr_t opaque,
				 AclEntryBase *acl_entry_base,
				 void (*format_who)(StringInfo out, intptr_t opaque))
{
	appendStringInfoChar(out, ace_type_chars[acl_entry_base->type - 1]);

	appendStringInfoChar(out, '/');
	format_mask(out, acl_entry_base->flags, ace_flag_chars);

	appendStringInfoChar(out, '/');
	format_who(out, opaque);

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

	if (acl == NULL)
		return implicit_allow ? mask : 0;

	check_acl(acl);

	num = ArrayGetNItems(ARR_NDIM(acl), ARR_DIMS(acl));
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
					granted |= mask & base->mask;

				mask &= ~base->mask;
			}
		}

		entry = att_addlength_pointer(entry, typlen, entry);
		entry = (char *) att_align_nominal(entry, typalign);
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

ArrayType *
merge_acls(const ArrayType *parent_acl, const ArrayType *acl,
		   int16 typlen, char typalign,
		   AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
		   bool container, bool deny_first)
{
	ArrayType	   *result;
	int				maxbytes;
	int				items;
	char		   *ptr;
	char		   *result_ptr;
	int				result_items = 0;

	if (parent_acl != NULL)
		check_acl(parent_acl);

	check_acl(acl);

	items = ArrayGetNItems(ARR_NDIM(acl), ARR_DIMS(acl));
	ptr = ARR_DATA_PTR(acl);

	maxbytes = ARR_OVERHEAD_NONULLS(1);
	maxbytes += ARR_SIZE(acl) - ARR_DATA_OFFSET(acl);
	if (parent_acl != NULL)
		maxbytes += ARR_SIZE(parent_acl) - ARR_DATA_OFFSET(parent_acl);

	result = (ArrayType *) palloc0(maxbytes);
	result->ndim = 1;
	result->elemtype = ARR_ELEMTYPE(acl);
	ARR_LBOUND(result)[0] = 1;

	result_ptr = ARR_DATA_PTR(result);

	if (!deny_first)
	{
		result_ptr = copy_acl_entries(ptr, result_ptr, items,
									  typlen, typalign, &result_items,
									  filter_not_inherited, NULL,
									  extract_acl_entry_base);
	}
	else
	{
		result_ptr = copy_acl_entries(ptr, result_ptr, items,
									  typlen, typalign, &result_items,
									  filter_access_denied, NULL,
									  extract_acl_entry_base);
		result_ptr = copy_acl_entries(ptr, result_ptr, items,
									  typlen, typalign, &result_items,
									  filter_access_allowed, NULL,
									  extract_acl_entry_base);
	}

	if (parent_acl != NULL)
		result_ptr = copy_acl_entries(ARR_DATA_PTR(parent_acl), result_ptr,
									  ArrayGetNItems(ARR_NDIM(parent_acl),
													 ARR_DIMS(parent_acl)),
									  typlen, typalign, &result_items,
									  container ? filter_inherited_container
												: filter_inherited_object,
									  container ? modify_inherited_container
												: modify_inherited_object,
									  extract_acl_entry_base);

	ARR_DIMS(result)[0] = result_items;
	SET_VARSIZE(result, ARR_OVERHEAD_NONULLS(1) +
						(result_ptr - ARR_DATA_PTR(result)));

	return result;
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
	if (ARR_NDIM(acl) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("ACL arrays must be one-dimensional")));

	if (ARR_HASNULL(acl))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("ACL arrays must not contain null values")));
}

static char *
copy_acl_entries(char *src, char *dest, int nitems, int typlen, char typalign,
				 int *ncopied, bool (*filter)(AclEntryBase *entry),
				 void (*modify_entry)(AclEntryBase *src, AclEntryBase *dest),
				 AclEntryBase * (*extract_acl_entry_base)(void *acl_entry))
{
	int			i;

	for (i = 0; i < nitems; ++i)
	{
		AclEntryBase   *entry;
		char		   *ptr;

		ptr = att_addlength_pointer(src, typlen, src);

		entry = extract_acl_entry_base(src);
		if (filter(entry))
		{
			memcpy(dest, src, ptr - src);

			if (modify_entry != NULL)
			{
				modify_entry(entry, extract_acl_entry_base(dest));
			}

			dest = att_addlength_pointer(dest, typlen, dest);
			dest = (char *) att_align_nominal(dest, typalign);

			++*ncopied;
		}

		src = (char *) att_align_nominal(ptr, typalign);
	}

	return dest;
}

static bool
filter_not_inherited(AclEntryBase *entry)
{
	return (entry->flags & ACE_INHERITED) == 0;
}

static bool
filter_access_denied(AclEntryBase *entry)
{
	return (entry->type == ACE_ACCESS_DENIED) &&
		   !(entry->flags & ACE_INHERITED);
}

static bool
filter_access_allowed(AclEntryBase *entry)
{
	return (entry->type == ACE_ACCESS_ALLOWED) &&
		   !(entry->flags & ACE_INHERITED);
}

static bool
filter_inherited_container(AclEntryBase *entry)
{
	if (entry->flags & ACE_NO_PROPAGATE_INHERIT)
		return (entry->flags & ACE_CONTAINER_INHERIT) != 0;
	else
		return (entry->flags & ACE_OBJECT_INHERIT) ||
			   (entry->flags & ACE_CONTAINER_INHERIT);
}

static bool
filter_inherited_object(AclEntryBase *entry)
{
	return (entry->flags & ACE_OBJECT_INHERIT) != 0;
}

static void
modify_inherited_container(AclEntryBase *src, AclEntryBase *dest)
{
	if (src->flags & ACE_NO_PROPAGATE_INHERIT)
	{
		if (src->flags & ACE_CONTAINER_INHERIT)
			dest->flags = 0;
	}
	else if (src->flags & ACE_OBJECT_INHERIT)
	{
		dest->flags |= ACE_INHERIT_ONLY;
	}

	dest->flags |= ACE_INHERITED;
}

static void
modify_inherited_object(AclEntryBase *src, AclEntryBase *dest)
{
	if (src->flags & ACE_OBJECT_INHERIT)
		dest->flags = 0;

	dest->flags |= ACE_INHERITED;
}
