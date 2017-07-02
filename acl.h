/* -------------------------------------------------------------------------
 *
 * acl.h
 *
 * Copyright (c) 2015-2016 Vladislav Arkhipov <vlad@arkhipov.ru>
 *
 * -------------------------------------------------------------------------
 */
#ifndef __ACL_H__
#define __ACL_H__

#include "lib/stringinfo.h"
#include "utils/array.h"

/* ACE types */
#define ACE_ACCESS_ALLOWED				0x00000001
#define ACE_ACCESS_DENIED				0x00000002

/* ACE flags
 * 0-15 application-specific
 * 16-31 reserved */
#define ACE_INHERIT_ONLY				0x80000000
#define ACE_OBJECT_INHERIT				0x40000000
#define ACE_CONTAINER_INHERIT			0x20000000
#define ACE_NO_PROPAGATE_INHERIT		0x10000000
#define ACE_INHERITED					0x08000000
#define ACE_INVALID						0x04000000

#define ACE_FLAGS_APPLICATION_SPECIFIC	0x0000FFFF

/* ACE access rights
 * 0-15 application-specific
 * 16-31 reserved */
#define ACE_READ						0x80000000
#define ACE_WRITE						0x40000000
#define ACE_DELETE						0x20000000
#define ACE_READ_ACL					0x10000000
#define ACE_WRITE_ACL					0x08000000

typedef struct AclEntryBase {
	uint32			type;
	uint32			flags;
	uint32			mask;
} AclEntryBase;

void parse_acl_entry(const char *s, AclEntryBase *acl_entry_base,
					 void *opaque,
					 const char *parse_who(const char *s, void *opaque));

void format_acl_entry(StringInfo out, intptr_t opaque,
					  AclEntryBase *acl_entry_base,
					  void (*format_who)(StringInfo out, intptr_t opaque));

uint32 check_access(const ArrayType *acl, int16 typlen, char typalign,
					AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
					uint32 mask, intptr_t who,
					bool (*who_matches)(void *acl_entry, intptr_t who),
					bool implicit_allow);

text *check_access_text_mask(const ArrayType *acl, int16 typlen,
							 char typalign,
							 AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
							 text *text_mask, intptr_t who,
							 bool (*who_matches)(void *acl_entry, intptr_t who),
							 bool implicit_allow);

ArrayType *merge_acls(const ArrayType *parent_acl, const ArrayType *acl,
					  int16 typlem, char typalign,
					  AclEntryBase * (*extract_acl_entry_base)(void *acl_entry),
					  bool container, bool deny_first);

#endif
