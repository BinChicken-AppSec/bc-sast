#!/usr/bin/env bash
# Apply the schema and run the row-level security tests.
#
# Usage:
#   ./db/test/run.sh                 # against db/docker-compose.yml
#   PGHOST=... PGPORT=... ./db/test/run.sh
#
# ON_ERROR_STOP=1 is what turns a failed assertion into a failed run; the
# test file raises on failure and psql would otherwise keep going and
# exit 0.
set -euo pipefail

export PGHOST="${PGHOST:-127.0.0.1}"
export PGPORT="${PGPORT:-55432}"
export PGUSER="${PGUSER:-bcsast}"
export PGPASSWORD="${PGPASSWORD:-bcsast-test-only}"
export PGDATABASE="${PGDATABASE:-bcsast}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==> waiting for postgres at $PGHOST:$PGPORT"
for _ in $(seq 1 60); do
  if psql -qtAc 'SELECT 1' >/dev/null 2>&1; then break; fi
  sleep 1
done
psql -qtAc 'SELECT version()' | sed 's/^/    /'

# Re-runnable, but only against something that is clearly a test database.
#
# The schema is not idempotent, so a second run needs the tables dropped
# first. Dropping a schema is destructive, and this script reads its
# target from the environment, so it refuses unless the database name
# says test. Without that guard a mistyped PGDATABASE would drop real
# tables and report it as a passing test run.
case "$PGDATABASE" in
  *test*|bcsast)
    psql -qc 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;' ;;
  *)
    echo "refusing to reset '$PGDATABASE': the name must contain 'test'" >&2
    echo "(this script drops and recreates the public schema)" >&2
    exit 2 ;;
esac

echo "==> applying schema"
psql -v ON_ERROR_STOP=1 -q -f "$root/db/schema.sql"

echo "==> row-level security tests"
# Count the assertions, do not just trust the closing line.
#
# `All row-level security tests passed.` at the end of the file is an
# \echo: it prints whether or not any DO block ran. A test file that
# silently asserted nothing -- a bad grep, a renamed table, an \if that
# skipped the body -- would produce a job log identical to a passing one.
# So the per-assertion NOTICEs are shown, counted, and compared against
# the number the file actually contains.
expected="$(grep -cE "RAISE NOTICE 'ok " "$root/db/test/rls_test.sql")"
out="$(psql -v ON_ERROR_STOP=1 -f "$root/db/test/rls_test.sql" 2>&1)"
echo "$out" | grep -oE 'ok [0-9]+ -- .*' | sed 's/^/    /'
got="$(printf '%s\n' "$out" | grep -cE 'NOTICE:  ok [0-9]+ -- ' || true)"
if [ "$got" -ne "$expected" ]; then
  echo "    FAIL: $got assertion(s) reported, expected $expected" >&2
  printf '%s\n' "$out" | sed 's/^/    | /' >&2
  exit 1
fi
echo "    $got of $expected assertions reported"

echo "==> done"
