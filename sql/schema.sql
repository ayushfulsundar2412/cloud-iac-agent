CREATE TABLE scans (
    id          SERIAL PRIMARY KEY,
    account_id  TEXT NOT NULL,
    region      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE resources (
    id                SERIAL PRIMARY KEY,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    resource_type     TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    name              TEXT,
    app               TEXT NOT NULL DEFAULT 'shared',
    config            JSONB NOT NULL DEFAULT '{}',
    monthly_cost_usd  NUMERIC(10,2),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE resource_dependencies (
    id                SERIAL PRIMARY KEY,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    from_resource_id  INTEGER NOT NULL REFERENCES resources(id),
    to_resource_id    INTEGER NOT NULL REFERENCES resources(id),
    relationship      TEXT NOT NULL,
    CHECK (from_resource_id <> to_resource_id),
    UNIQUE (from_resource_id, to_resource_id, relationship)
);

CREATE TABLE findings (
    id           SERIAL PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    resource_id  INTEGER NOT NULL REFERENCES resources(id),
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    category     TEXT NOT NULL CHECK (category IN ('risk', 'cost')),
    title        TEXT NOT NULL,
    detail       JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, resource_id, rule_id)
);