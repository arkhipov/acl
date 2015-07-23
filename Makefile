# acl/Makefile

MODULE_big = acl
OBJS = acl.o acl_oid.o

EXTENSION = acl
DATA = acl--1.0.0.sql
DOCS = acl.md

REGRESS = install acl_oid

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
