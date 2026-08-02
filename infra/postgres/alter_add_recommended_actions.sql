-- Apply on existing Postgres volumes that already ran init.sql.
-- Safe to re-run: ADD COLUMN IF NOT EXISTS.
ALTER TABLE analysis_results
    ADD COLUMN IF NOT EXISTS recommended_actions JSONB;
