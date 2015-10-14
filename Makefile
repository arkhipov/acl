# acl/Makefile

MODULE_big = acl
OBJS = acl.o acl_oid.o acl_uuid.o acl_int8.o acl_int4.o util.o

PG_CPPFLAGS=-Wall

EXTENSION = acl
DATA = acl--1.0.1.sql \
       acl--1.0.0--1.0.1.sql
DOCS = acl.md

REGRESS = install acl_oid acl_uuid acl_int8 acl_int4

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
