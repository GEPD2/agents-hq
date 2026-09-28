-- Daily KPI snapshots for the dashboard time-series tiles.
-- One row per day; the app upserts today's counts on load.
CREATE TABLE IF NOT EXISTS metrics_snapshots (
    snap_date     DATE        NOT NULL PRIMARY KEY,
    reports       INT         NOT NULL DEFAULT 0,
    kb_docs       INT         NOT NULL DEFAULT 0,
    threat_actors INT         NOT NULL DEFAULT 0,
    iocs          INT         NOT NULL DEFAULT 0,
    critical      INT         NOT NULL DEFAULT 0,
    taken_at      DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
