CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS apk_uploads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename      VARCHAR(255)  NOT NULL,
    sha256        VARCHAR(64)   NOT NULL UNIQUE,
    file_size     BIGINT,
    upload_time   TIMESTAMP     NOT NULL DEFAULT NOW(),
    status        VARCHAR(50)   NOT NULL DEFAULT 'pending',
    minio_path    VARCHAR(500)
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    apk_id          UUID NOT NULL REFERENCES apk_uploads(id) ON DELETE CASCADE,
    static_analysis JSONB,
    dynamic_analysis JSONB,
    threat_intel    JSONB,
    ai_summary      TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    apk_id           UUID NOT NULL REFERENCES apk_uploads(id) ON DELETE CASCADE,
    indicator_type   VARCHAR(100),
    indicator_value  TEXT,
    source           VARCHAR(100),
    severity         VARCHAR(50),
    mitre_technique  VARCHAR(50),
    created_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    apk_id            UUID NOT NULL REFERENCES apk_uploads(id) ON DELETE CASCADE,
    risk_score        FLOAT,
    severity          VARCHAR(50),
    classification    VARCHAR(100),
    fraud_intent      VARCHAR(200),
    fraud_journey     JSONB,
    executive_summary TEXT,
    recommendations   JSONB,
    mitre_mappings    JSONB,
    shap_explanations JSONB,
    created_at        TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fraud_journeys (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    apk_id     UUID NOT NULL REFERENCES apk_uploads(id) ON DELETE CASCADE,
    intent     VARCHAR(100),
    nodes      JSONB,
    edges      JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apk_sha256        ON apk_uploads(sha256);
CREATE INDEX IF NOT EXISTS idx_apk_status        ON apk_uploads(status);
CREATE INDEX IF NOT EXISTS idx_apk_upload_time   ON apk_uploads(upload_time DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_apk_id   ON analysis_results(apk_id);
CREATE INDEX IF NOT EXISTS idx_report_apk_id     ON risk_reports(apk_id);
CREATE INDEX IF NOT EXISTS idx_ti_apk_id         ON threat_indicators(apk_id);
