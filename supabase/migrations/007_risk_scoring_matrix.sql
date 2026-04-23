-- ============================================================
-- FortiGRC — Risk Scoring Matrix
-- Migration 007: Update Risks Table for Automated Scoring
-- ============================================================

-- Since quantitative_score was defined as GENERATED ALWAYS, we must DROP it,
-- insert the new manual score column, and add the matrix parameters.

ALTER TABLE risks
  DROP COLUMN quantitative_score,
  DROP COLUMN event_frequency,
  DROP COLUMN event_magnitude;

ALTER TABLE risks
  ADD COLUMN likelihood INTEGER CHECK (likelihood >= 1 AND likelihood <= 5),
  ADD COLUMN impact INTEGER CHECK (impact >= 1 AND impact <= 5),
  ADD COLUMN quantitative_score INTEGER,
  ADD COLUMN severity_level VARCHAR CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical'));
