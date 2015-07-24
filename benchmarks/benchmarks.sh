#!/bin/bash

dir=$(cd "$(dirname "$0")" && pwd)

count="$1"
if [[ -z $count ]]; then
  count=1000000
fi

ace_count="$2"
if [[ -z $ace_count ]]; then
  ace_count=20
fi

if [[ -z $PG_HOME ]]; then
  PG_HOME=$(dirname $(pg_config --bindir))
  if (( $? != 0 )); then
    exit 1
  fi
fi

pg_args=

if [[ -n $PG_USER ]]; then
  pg_args="$pg_args -U $PG_USER"
fi

if [[ -z $PG_DATABASE ]]; then
  PG_DATABASE="acl_benchmarks"
fi

psql_args="$pg_args -d $PG_DATABASE"

# Create database
"$PG_HOME"/bin/createdb $pg_args "$PG_DATABASE"
if [[ $? != 0 ]]; then
  exit 1
fi

# Install extensions
"$PG_HOME"/bin/psql $psql_args -f "$dir"/setup.sql

################################################################################
# OID
################################################################################

cat "$dir"/test_oid.sql | sed 's/$count/'$count'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

################################################################################
# UUID
################################################################################

cat "$dir"/test_uuid.sql | sed 's/$count/'$count'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

# Drop database
"$PG_HOME"/bin/dropdb $pg_args "$PG_DATABASE"
