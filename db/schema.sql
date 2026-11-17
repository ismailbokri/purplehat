-- PenTest AI — Schema for user-facing tables (auth, checklist, runs, findings).

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Replaces the original checklist JSON (palnner/checklist.json) as source of truth.
-- The "extra" JSONB column holds consultant-fill placeholders ("Résultat
-- effectif", "Commentaire Chef de projet", etc.) preserved from the original JSON.
CREATE TABLE IF NOT EXISTS checklist_tests (
    id                       SERIAL PRIMARY KEY,
    test_id                  TEXT NOT NULL,
    category                 TEXT NOT NULL,
    tests                    TEXT NOT NULL,
    outils                   TEXT NOT NULL DEFAULT '',
    commande                 TEXT NOT NULL DEFAULT '',
    ref_procedure            TEXT NOT NULL DEFAULT '',
    commentaires             TEXT NOT NULL DEFAULT '',
    resultat_attendu         TEXT NOT NULL DEFAULT '',
    vulnerabilite_attendue   TEXT NOT NULL DEFAULT '',
    bonne_pratique_attendu   TEXT NOT NULL DEFAULT '',
    extra                    JSONB NOT NULL DEFAULT '{}'::jsonb,
    position                 INT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_checklist_category ON checklist_tests(category);
CREATE INDEX IF NOT EXISTS idx_checklist_order    ON checklist_tests(category, position);

-- One row per pipeline run (POST /vtest)
CREATE TABLE IF NOT EXISTS pentest_runs (
    id                    SERIAL PRIMARY KEY,
    user_id               INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id            TEXT NOT NULL UNIQUE,
    target                TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'running'
                              CHECK (status IN ('running', 'complete', 'error')),
    selected_categories   JSONB NOT NULL DEFAULT '[]'::jsonb,
    skip_scan             BOOLEAN NOT NULL DEFAULT false,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at          TIMESTAMPTZ,
    error_message         TEXT,
    report_text_path      TEXT,
    report_pdf_path       TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_user      ON pentest_runs(user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_session   ON pentest_runs(session_id);

-- A pentest "engagement": one row groups many module runs (Découverte,
-- Pré-auth, Post-auth, …) executed against the same target with shared state
-- (discovered endpoints, auth cookies, custom endpoints, accumulated findings).
CREATE TABLE IF NOT EXISTS pentest_sessions (
    id                    SERIAL PRIMARY KEY,
    user_id               INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target                TEXT NOT NULL,
    host_port             TEXT,
    host_base_url         TEXT,
    custom_endpoints      JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_payload          JSONB NOT NULL DEFAULT '{}'::jsonb,
    state_snapshot        JSONB NOT NULL DEFAULT '{}'::jsonb,
    status                TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'closed', 'error')),
    last_report_pdf_path  TEXT,
    last_report_text_path TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON pentest_sessions(user_id, created_at DESC);

-- Assessment scope for a session. Rendered into a system-prompt block and
-- injected into every agent call so agents stay within authorized targets.
-- Shape: {in_scope: [], out_of_scope: [], authorized_domains: [],
--         restrictions: "", auth_requirements: "", notes: ""}
ALTER TABLE pentest_sessions ADD COLUMN IF NOT EXISTS scope JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Link existing pentest_runs to a parent session and tag with the module
-- it belongs to ('discovery', 'exploitation') or 'manual' for the per-session
-- bucket that holds tester-recorded findings. NULL on legacy /vtest runs.
ALTER TABLE pentest_runs ADD COLUMN IF NOT EXISTS pentest_session_id INT REFERENCES pentest_sessions(id) ON DELETE SET NULL;
ALTER TABLE pentest_runs ADD COLUMN IF NOT EXISTS module_key TEXT;
ALTER TABLE pentest_runs ADD COLUMN IF NOT EXISTS selected_test_ids JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_runs_session_fk ON pentest_runs(pentest_session_id, started_at DESC);

-- Curated cybersecurity news. Populated by a weekly background job; the UI
-- shows only the curated result (no AI traces, no confidence scores).
CREATE TABLE IF NOT EXISTS news_articles (
    id                     SERIAL PRIMARY KEY,
    url                    TEXT NOT NULL UNIQUE,
    content_hash           TEXT NOT NULL UNIQUE,
    title                  TEXT NOT NULL,
    summary                TEXT NOT NULL DEFAULT '',
    source                 TEXT NOT NULL DEFAULT '',
    affected_technologies  TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    published_at           TIMESTAMPTZ,
    fetched_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_news_published ON news_articles(published_at DESC NULLS LAST);

-- Small key/value store for module metadata (e.g. last_news_update timestamp).
CREATE TABLE IF NOT EXISTS app_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL DEFAULT ''
);

-- Per-phase chat history between the tester and a phase Conversation Agent.
CREATE TABLE IF NOT EXISTS chat_messages (
    id                    SERIAL PRIMARY KEY,
    pentest_session_id    INT NOT NULL REFERENCES pentest_sessions(id) ON DELETE CASCADE,
    phase                 TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content               TEXT NOT NULL DEFAULT '',
    suggestions           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_session_phase
    ON chat_messages(pentest_session_id, phase, created_at);

-- 1:N from pentest_runs. user_id is denormalized for fast lookups of
-- "all findings for user X".
CREATE TABLE IF NOT EXISTS findings (
    id                    SERIAL PRIMARY KEY,
    run_id                INT NOT NULL REFERENCES pentest_runs(id) ON DELETE CASCADE,
    user_id               INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    finding_id            TEXT,
    finding_timestamp     TIMESTAMPTZ,
    phase                 TEXT,
    test_status           TEXT NOT NULL
                              CHECK (test_status IN ('found', 'not_found', 'not_conclusive')),
    finding               TEXT NOT NULL DEFAULT '',
    owasp_id              TEXT NOT NULL DEFAULT '',
    owasp_category        TEXT NOT NULL DEFAULT '',
    checklist_test_id     TEXT NOT NULL DEFAULT '',
    checklist_category    TEXT NOT NULL DEFAULT '',
    test_description      TEXT NOT NULL DEFAULT '',
    vuln_attendue         TEXT NOT NULL DEFAULT '',
    severity              TEXT NOT NULL DEFAULT '',
    cvss                  NUMERIC,
    cvss_vector           TEXT NOT NULL DEFAULT '',
    cve                   TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    command               TEXT NOT NULL DEFAULT '',
    output_snippet        TEXT NOT NULL DEFAULT '',
    exploit_refs          TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    cvss_records          JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_run     ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_user    ON findings(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status  ON findings(run_id, test_status);
