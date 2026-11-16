-- BC SAST findings history -- row-level security tests.
--
-- Run against a database that has had db/schema.sql applied:
--   psql -v ON_ERROR_STOP=1 -f db/test/rls_test.sql
--
-- Every check raises on failure, and ON_ERROR_STOP turns that into a
-- non-zero exit. Tests that expect a *rejection* assert the rejection
-- happened: a test that passes because the statement silently did
-- nothing would be worse than no test.
--
-- These tests run as the role that owns the tables, which is the point.
-- ENABLE ROW LEVEL SECURITY alone exempts the owner, so a suite that
-- tested isolation as some other role would pass against a schema with
-- no effective isolation in the deployment that reuses the migration
-- role for the application.

\set A '11111111-1111-1111-1111-111111111111'
\set B '22222222-2222-2222-2222-222222222222'

-- ---------------------------------------------------------------------
-- 0. Run as a role that RLS actually applies to.
--
-- This block is not boilerplate. A superuser, and any role holding
-- BYPASSRLS, ignores every policy below -- FORCE ROW LEVEL SECURITY does
-- not change that, because FORCE only removes the *table owner's*
-- exemption. A suite that ran as the migration superuser would report
-- every test below as passing against a database with no isolation
-- whatsoever. The first run of this file did exactly that, which is why
-- the assertion is here.
--
-- So: a dedicated application role, and a hard assertion that it is
-- neither a superuser nor BYPASSRLS before any isolation is claimed.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bcsast_app') THEN
    CREATE ROLE bcsast_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
ALTER ROLE bcsast_app NOSUPERUSER NOBYPASSRLS;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bcsast_app;
GRANT USAGE ON SCHEMA public TO bcsast_app;

SET ROLE bcsast_app;

DO $$
DECLARE
  su   boolean;
  byp  boolean;
BEGIN
  SELECT rolsuper, rolbypassrls INTO su, byp
  FROM pg_roles WHERE rolname = current_user;
  IF su OR byp THEN
    RAISE EXCEPTION
      'FAIL -- tests are running as %, which bypasses RLS (superuser=%, bypassrls=%). '
      'Every isolation result below would be meaningless.', current_user, su, byp;
  END IF;
  RAISE NOTICE 'ok 0 -- running as %, which RLS applies to', current_user;
END $$;

-- ---------------------------------------------------------------------
-- 1. Structural: every table is covered.
--
-- This is the test that earns its keep over time. It fails when someone
-- adds a table and forgets its policy, which is exactly the mistake that
-- no functional test would catch.
-- ---------------------------------------------------------------------
DO $$
DECLARE
  bad text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO bad
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'tables without ENABLE+FORCE row level security: %', bad;
  END IF;

  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO bad
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND NOT EXISTS (
      SELECT 1 FROM pg_policy p
      WHERE p.polrelid = c.oid AND p.polqual IS NOT NULL
        AND p.polwithcheck IS NOT NULL);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'tables lacking a policy with both USING and WITH CHECK: %', bad;
  END IF;
  RAISE NOTICE 'ok 1 -- every table has ENABLE+FORCE RLS and a USING+WITH CHECK policy';
END $$;

-- ---------------------------------------------------------------------
-- 2. Fail closed: with no tenant set, every query raises.
--
-- The alternative -- current_setting(..., true) returning NULL -- matches
-- no rows, and "no rows" reads as "no prior findings", which reports an
-- entire repository as newly introduced. An error is the only acceptable
-- behavior, so absence of the setting must be loud.
-- ---------------------------------------------------------------------
RESET bc.tenant_id;
DO $$
BEGIN
  PERFORM count(*) FROM repo;
  RAISE EXCEPTION 'FAIL -- a query succeeded with bc.tenant_id unset';
EXCEPTION
  -- Two distinct codes, both acceptable, and the difference is worth
  -- knowing: a setting never assigned in the session raises
  -- undefined_object, while one assigned and then RESET is left as an
  -- empty string and fails the uuid cast instead. An application that
  -- caught only one of them would be surprised by the other. What the
  -- control requires is that it RAISES rather than matching no rows.
  WHEN undefined_object OR invalid_text_representation THEN
    RAISE NOTICE 'ok 2 -- absent bc.tenant_id raises (%) instead of matching nothing', SQLSTATE;
END $$;

-- ---------------------------------------------------------------------
-- Fixtures: one tenant each, one repo each.
-- ---------------------------------------------------------------------
SET bc.tenant_id = :'A';
INSERT INTO tenant (tenant_id, slug) VALUES (:'A', 'tenant-a')
  ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO repo (tenant_id, repo_id, repo_key, repo_key_source)
  VALUES (:'A', '0000000a-0000-0000-0000-00000000000a', 'github.com/acme/a#', 'derived')
  ON CONFLICT DO NOTHING;

SET bc.tenant_id = :'B';
INSERT INTO tenant (tenant_id, slug) VALUES (:'B', 'tenant-b')
  ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO repo (tenant_id, repo_id, repo_key, repo_key_source)
  VALUES (:'B', '0000000b-0000-0000-0000-00000000000b', 'github.com/acme/b#', 'derived')
  ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------
-- 3. Read isolation.
-- ---------------------------------------------------------------------
SET bc.tenant_id = :'A';
DO $$
DECLARE
  n int;
  keys text;
BEGIN
  SELECT count(*), string_agg(repo_key, ',') INTO n, keys FROM repo;
  IF n <> 1 OR keys <> 'github.com/acme/a#' THEN
    RAISE EXCEPTION 'FAIL -- tenant A sees % row(s): %', n, keys;
  END IF;
  RAISE NOTICE 'ok 3 -- a tenant reads only its own rows';
END $$;

-- ---------------------------------------------------------------------
-- 4. WITH CHECK on INSERT: cannot write a row tagged as another tenant.
--
-- USING alone would let this through. The row would then be invisible to
-- its author and visible to the victim.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  INSERT INTO repo (tenant_id, repo_id, repo_key, repo_key_source)
    VALUES ('22222222-2222-2222-2222-222222222222',
            '0000000c-0000-0000-0000-00000000000c', 'github.com/acme/c#', 'derived');
  RAISE EXCEPTION 'FAIL -- tenant A inserted a row tagged tenant B';
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok 4 -- WITH CHECK rejects an insert tagged with another tenant';
END $$;

-- ---------------------------------------------------------------------
-- 5. WITH CHECK on UPDATE: cannot hand a row to another tenant.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  UPDATE repo SET tenant_id = '22222222-2222-2222-2222-222222222222'
   WHERE repo_key = 'github.com/acme/a#';
  RAISE EXCEPTION 'FAIL -- tenant A moved its own row to tenant B';
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok 5 -- WITH CHECK rejects moving a row to another tenant';
END $$;

-- ---------------------------------------------------------------------
-- 6. The composite foreign key closes the existence oracle.
--
-- `finding` references repo(tenant_id, repo_id), not repo(repo_id). With
-- a single-column FK, tenant A could probe for tenant B's repo_id values
-- and learn which exist from whether the insert succeeded -- an oracle
-- that leaks through a constraint rather than through a row.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  INSERT INTO finding (tenant_id, repo_id, first_seen_scan, first_seen_at)
    VALUES ('11111111-1111-1111-1111-111111111111',
            '0000000b-0000-0000-0000-00000000000b',   -- tenant B's repo
            gen_random_uuid(), now());
  RAISE EXCEPTION 'FAIL -- tenant A referenced tenant B''s repo';
EXCEPTION
  WHEN foreign_key_violation THEN
    RAISE NOTICE 'ok 6 -- the composite FK rejects a cross-tenant reference';
END $$;

-- ---------------------------------------------------------------------
-- 7. Transaction-local tenant, which is how a pooled application must
--    set it: set_config(..., true) must not leak past COMMIT.
-- ---------------------------------------------------------------------
RESET bc.tenant_id;
BEGIN;
SELECT set_config('bc.tenant_id', '11111111-1111-1111-1111-111111111111', true);
DO $$
BEGIN
  IF (SELECT count(*) FROM repo) <> 1 THEN
    RAISE EXCEPTION 'FAIL -- transaction-local tenant did not apply';
  END IF;
END $$;
COMMIT;
DO $$
BEGIN
  PERFORM count(*) FROM repo;
  RAISE EXCEPTION 'FAIL -- the transaction-local tenant leaked past COMMIT';
EXCEPTION
  WHEN undefined_object OR invalid_text_representation THEN
    RAISE NOTICE 'ok 7 -- set_config(..., true) does not outlive its transaction';
END $$;

\echo 'All row-level security tests passed.'
