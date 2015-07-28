# acl/Makefile

MODULE_big = acl
OBJS = acl.o acl_oid.o acl_uuid.o acl_int8.o

EXTENSION = acl
DATA = acl--1.0.0.sql
DOCS = acl.md

REGRESS = install acl_oid acl_uuid acl_int8

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
