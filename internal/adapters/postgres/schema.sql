-- Gjallar operational schema. Idempotent: safe to run on every start.
CREATE TABLE IF NOT EXISTS images (
    digest        TEXT PRIMARY KEY,
    repository    TEXT NOT NULL,
    tag           TEXT NOT NULL DEFAULT '',
    distro        TEXT NOT NULL DEFAULT '',
    packages      INT  NOT NULL DEFAULT 0,
    sbom_ready    BOOLEAN NOT NULL DEFAULT FALSE,
    sbom_queued   TIMESTAMPTZ,
    db_version    TEXT NOT NULL DEFAULT '',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scanned  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS workloads (
    id          TEXT PRIMARY KEY,           -- cluster/namespace/kind/name
    cluster     TEXT NOT NULL,
    namespace   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    exposed     BOOLEAN NOT NULL DEFAULT FALSE,
    spec        JSONB NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS workloads_ns ON workloads (namespace);

CREATE TABLE IF NOT EXISTS workload_images (
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    container   TEXT NOT NULL,
    digest      TEXT NOT NULL,
    PRIMARY KEY (workload_id, container)
);
CREATE INDEX IF NOT EXISTS workload_images_digest ON workload_images (digest);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    digest      TEXT NOT NULL,
    vuln_id     TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    pkg_type    TEXT NOT NULL DEFAULT '',
    fixed_in    TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL,
    cvss        REAL NOT NULL DEFAULT 0,
    epss        REAL NOT NULL DEFAULT 0,
    kev         BOOLEAN NOT NULL DEFAULT FALSE,
    state       TEXT NOT NULL,
    risk        INT  NOT NULL DEFAULT 0,
    band        TEXT NOT NULL DEFAULT 'low',
    actionable  BOOLEAN NOT NULL DEFAULT FALSE,
    reasons     JSONB NOT NULL DEFAULT '[]',
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    fixed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS findings_digest ON findings (digest);
CREATE INDEX IF NOT EXISTS findings_open ON findings (state, risk DESC);
CREATE INDEX IF NOT EXISTS findings_pkg ON findings (package);

CREATE TABLE IF NOT EXISTS exceptions (
    finding_id  TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    author      TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS licenses (
    digest   TEXT NOT NULL,
    package  TEXT NOT NULL,
    version  TEXT NOT NULL DEFAULT '',
    license  TEXT NOT NULL,
    verdict  TEXT NOT NULL,
    PRIMARY KEY (digest, package, version, license)
);
CREATE INDEX IF NOT EXISTS licenses_verdict ON licenses (verdict);

CREATE TABLE IF NOT EXISTS posture (
    workload_id TEXT NOT NULL,
    check_id    TEXT NOT NULL,
    container   TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workload_id, check_id, container)
);

CREATE TABLE IF NOT EXISTS patches (
    id          BIGSERIAL PRIMARY KEY,
    digest      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',
    patched_ref TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2026-11: which matcher reported a finding when not the primary one (OSV).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
