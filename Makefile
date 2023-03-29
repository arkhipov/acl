# acl/Makefile

MODULE_big = acl
OBJS = acl.o acl_oid.o acl_uuid.o acl_int8.o acl_int4.o util.o

PG_CPPFLAGS=-Wall

EXTENSION = acl
DATA = acl--1.0.2.sql \
       acl--1.0.0--1.0.1.sql \
       acl--1.0.1--1.0.2.sql
DOCS = acl.md

PG_CONFIG = pg_config
PG_VERSION := $(shell $(PG_CONFIG) --version | cut -d '.' -f 1 | cut -d ' ' -f 2)

ifeq ($(shell test $(PG_VERSION) -ge 10; echo $$?), 0)
  REGRESS = install acl_oid acl_uuid_pg10 acl_int8 acl_int4
else
  REGRESS = install acl_oid acl_uuid acl_int8 acl_int4
endif

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
