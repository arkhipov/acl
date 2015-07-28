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

unique_aces="$3"
if [[ -z $unique_aces ]]; then
  unique_aces=1000
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

echo "Testing OID-based ACEs..."
cat "$dir"/test_oid.sql | sed 's/$count/'$count'/' | sed 's/$unique_aces/'$unique_aces'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

################################################################################
# UUID
################################################################################

echo "Testing UUID-based ACEs..."
cat "$dir"/test_uuid.sql | sed 's/$count/'$count'/' | sed 's/$unique_aces/'$unique_aces'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

################################################################################
# int4
################################################################################

echo "Testing int4-based ACEs..."
cat "$dir"/test_int4.sql | sed 's/$count/'$count'/' | sed 's/$unique_aces/'$unique_aces'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

################################################################################
# int8
################################################################################

echo "Testing int8-based ACEs..."
cat "$dir"/test_int8.sql | sed 's/$count/'$count'/' | sed 's/$unique_aces/'$unique_aces'/' | sed 's/$ace_count/'$ace_count'/' | "$PG_HOME"/bin/psql $psql_args

# Drop database
"$PG_HOME"/bin/dropdb $pg_args "$PG_DATABASE"
