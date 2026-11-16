-- BC SAST findings history -- schema.
--
-- Generated from docs/findings-history-design.md's schema block, which is
-- the source of truth for the table definitions. The row-level security
-- below is written out per table; the design doc states one policy and
-- says "repeated for every table above", which is not something a
-- deployment can apply.
--
-- PG 14 compatible. No extensions: gen_random_uuid() is core from PG 13.
--
-- Apply with:  psql -v ON_ERROR_STOP=1 -f db/schema.sql
-- Verify with: psql -v ON_ERROR_STOP=1 -f db/test/rls_test.sql

BEGIN;

-- No extensions. gen_random_uuid() is core from PG 13.

CREATE TABLE tenant (
  tenant_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE repo (
  tenant_id       uuid NOT NULL REFERENCES tenant(tenant_id),
  repo_id         uuid NOT NULL DEFAULT gen_random_uuid(),
  repo_key        text NOT NULL,   -- normalized origin + subtree, credentials stripped
  repo_key_source text NOT NULL    -- 'explicit' | 'env' | 'derived'
    CHECK (repo_key_source IN ('explicit','env','derived')),
  root_commit     text,            -- identity proof; NULL until a non-shallow clone
  root_commit_verified boolean NOT NULL DEFAULT false,
  origin_display  text,            -- for humans; never the match key
  repo_name       text,
  app_id          text,
  default_branch  text NOT NULL DEFAULT 'main',
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, repo_id),
  UNIQUE (tenant_id, repo_key)
);

CREATE TABLE scan (
  tenant_id        uuid NOT NULL,
  scan_id          uuid NOT NULL DEFAULT gen_random_uuid(),
  repo_id          uuid NOT NULL,
  label            text NOT NULL,   -- today's metrics.scan_id, not unique
  branch           text,
  commit_sha       text,
  base_commit_sha  text,            -- merge-base, for a PR scan
  worktree_dirty   boolean NOT NULL DEFAULT false,
  tool_version     text NOT NULL,
  engine_id        text NOT NULL,
  engine_version   text NOT NULL,
  model            text NOT NULL,
  dialect          text NOT NULL,
  base_host        text NOT NULL,
  config_digest    text NOT NULL,
  coverage_mode    text NOT NULL CHECK (coverage_mode IN ('full','diff')),
  stages_ran       text[] NOT NULL DEFAULT '{}',
  completeness     text NOT NULL
    CHECK (completeness IN ('running','complete','budget_stopped',
                            'canceled','degraded','failed','abandoned')),
  completeness_detail text NOT NULL DEFAULT '',
  started_at       timestamptz NOT NULL,
  heartbeat_at     timestamptz NOT NULL,
  finished_at      timestamptz,
  cost_usd         numeric(12,4),
  PRIMARY KEY (tenant_id, scan_id),
  FOREIGN KEY (tenant_id, repo_id) REFERENCES repo(tenant_id, repo_id)
);
CREATE INDEX ON scan (tenant_id, repo_id, branch, started_at DESC);

-- One row per file that was NOT reviewed, plus, for a diff-scoped scan,
-- one per file that was. See "Closing the gaps" for the disposition
-- values and why the table stores the exceptions rather than the set.
CREATE TABLE scan_coverage (
  tenant_id   uuid NOT NULL,
  scan_id     uuid NOT NULL,
  path        text NOT NULL,
  disposition text NOT NULL CHECK (disposition IN (
    'reviewed','not_eligible','auto_excluded','config_excluded',
    'unreachable','out_of_diff_scope','chunk_failed','chunk_guardrailed',
    'budget_skipped','canceled','unchunked')),
  detail      text NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, scan_id, path),
  FOREIGN KEY (tenant_id, scan_id) REFERENCES scan(tenant_id, scan_id) ON DELETE CASCADE
);

CREATE TABLE finding (
  tenant_id       uuid NOT NULL,
  finding_id      uuid NOT NULL DEFAULT gen_random_uuid(),
  repo_id         uuid NOT NULL,
  first_seen_scan uuid NOT NULL,
  first_seen_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, finding_id),
  FOREIGN KEY (tenant_id, repo_id) REFERENCES repo(tenant_id, repo_id)
);

-- The ladder's index. A new scheme is new rows, never a migration.
-- Append-only and never reassigned, so a finding stays matchable by every
-- key it has ever had.
CREATE TABLE finding_key (
  tenant_id  uuid NOT NULL,
  repo_id    uuid NOT NULL,
  scheme     text NOT NULL,         -- 'bc/findingId/v1' | '/v2' | '/v3' | 'move/v1'
  key        text NOT NULL,
  finding_id uuid NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, repo_id, scheme, key),
  FOREIGN KEY (tenant_id, finding_id) REFERENCES finding(tenant_id, finding_id) ON DELETE CASCADE
);
CREATE INDEX ON finding_key (tenant_id, finding_id);

CREATE TABLE observation (
  tenant_id  uuid NOT NULL,
  scan_id    uuid NOT NULL,
  finding_id uuid NOT NULL,
  match_tier smallint NOT NULL,
  path       text NOT NULL,
  line_start integer NOT NULL,
  line_end   integer NOT NULL,
  vuln_class text NOT NULL,
  cwe        text,
  severity   text NOT NULL,
  confidence real,
  verdict    text,
  title      text NOT NULL,
  evidence   jsonb NOT NULL,   -- [{"path": ..., "content_sha": ...}, ...]
  payload    jsonb,            -- full RankedFinding; NULL unless opted in
  PRIMARY KEY (tenant_id, scan_id, finding_id),
  FOREIGN KEY (tenant_id, scan_id)    REFERENCES scan(tenant_id, scan_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, finding_id) REFERENCES finding(tenant_id, finding_id) ON DELETE CASCADE
);

CREATE TABLE triage (
  tenant_id  uuid NOT NULL,
  triage_id  uuid NOT NULL DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL,
  decision   text NOT NULL
    CHECK (decision IN ('false_positive','accepted_risk','wont_fix','reopen')),
  reason     text NOT NULL CHECK (length(btrim(reason)) >= 10),
  decided_by text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, triage_id),
  FOREIGN KEY (tenant_id, finding_id) REFERENCES finding(tenant_id, finding_id) ON DELETE CASCADE,
  CHECK (decision <> 'accepted_risk' OR expires_at IS NOT NULL)
);

-- A projection, not a source of truth. Rebuildable from observation +
-- scan_coverage + triage at any time, which is what makes the resolution
-- rule safe to change later.
CREATE TABLE finding_state (
  tenant_id          uuid NOT NULL,
  finding_id         uuid NOT NULL,
  state              text NOT NULL
    CHECK (state IN ('open','fix_pending','fixed','reopened','suppressed')),
  last_seen_scan     uuid,
  last_absent_scan   uuid,
  absent_streak      integer NOT NULL DEFAULT 0,
  fix_confirmed_by   text,    -- 'recheck' | 'streak' | NULL
  derivation_version integer NOT NULL,
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, finding_id)
);

-- ---------------------------------------------------------------------
-- Row-level security
--
-- Three details decide whether this is a control or decoration, and
-- all three are deliberate:
--
--   * `missing_ok = false` on current_setting. An application that
--     forgets to set the tenant gets an error on every query. The
--     alternative returns NULL, silently matches nothing, and
--     "nothing" reads as "no prior findings" -- which reports every
--     finding in the repository as newly introduced.
--   * FORCE ROW LEVEL SECURITY. ENABLE alone exempts the table
--     owner, and the owner is whoever ran the migrations. Without
--     FORCE, a deployment that reuses the migration role for the
--     application has no isolation at all and looks fine in testing.
--   * WITH CHECK as well as USING. USING filters reads; without
--     WITH CHECK a tenant can still WRITE a row tagged with someone
--     else's tenant_id.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION bc_tenant() RETURNS uuid
  LANGUAGE sql STABLE AS
  $$ SELECT current_setting('bc.tenant_id', false)::uuid $$;

ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_tenant ON tenant
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE repo ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo FORCE  ROW LEVEL SECURITY;
CREATE POLICY repo_tenant ON repo
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE scan ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan FORCE  ROW LEVEL SECURITY;
CREATE POLICY scan_tenant ON scan
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE scan_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_coverage FORCE  ROW LEVEL SECURITY;
CREATE POLICY scan_coverage_tenant ON scan_coverage
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding FORCE  ROW LEVEL SECURITY;
CREATE POLICY finding_tenant ON finding
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE finding_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_key FORCE  ROW LEVEL SECURITY;
CREATE POLICY finding_key_tenant ON finding_key
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE observation ENABLE ROW LEVEL SECURITY;
ALTER TABLE observation FORCE  ROW LEVEL SECURITY;
CREATE POLICY observation_tenant ON observation
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE triage ENABLE ROW LEVEL SECURITY;
ALTER TABLE triage FORCE  ROW LEVEL SECURITY;
CREATE POLICY triage_tenant ON triage
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

ALTER TABLE finding_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_state FORCE  ROW LEVEL SECURITY;
CREATE POLICY finding_state_tenant ON finding_state
  USING      (tenant_id = bc_tenant())
  WITH CHECK (tenant_id = bc_tenant());

COMMIT;
