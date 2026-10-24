-- Ledger schema and seed data for Suspicious Package Detonator
-- This file is mounted into Postgres via docker-entrypoint-initdb.d

CREATE TABLE IF NOT EXISTS runs (
    id              SERIAL PRIMARY KEY,
    run_id          TEXT UNIQUE NOT NULL,
    sandbox_name    TEXT NOT NULL,
    problem_id      TEXT NOT NULL DEFAULT 'package-detonation',
    state           TEXT NOT NULL DEFAULT 'created'
                    CHECK (state IN ('created','ready','running','succeeded','failed','deleted',
                                     'mid_task_failure','resumed','rolled_back','fresh_start')),
    execution_target TEXT NOT NULL DEFAULT 'celesto_sandbox'
                    CHECK (execution_target = 'celesto_sandbox'),
    boot_to_ready_s REAL,
    wall_clock_s    REAL,
    cost_usd        REAL,
    verdict         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed row for judges' smoke test (idempotent)
INSERT INTO runs (run_id, sandbox_name, state, execution_target)
VALUES ('seed-demo-1', 'sbx-seeddemo1', 'deleted', 'celesto_sandbox')
ON CONFLICT (run_id) DO NOTHING;
