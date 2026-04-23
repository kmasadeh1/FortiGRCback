-- ============================================================
-- FortiGRC — Vulnerability Ingestion API
-- Migration 008: Add source tracking to Risks Table
-- ============================================================

ALTER TABLE risks
  ADD COLUMN IF NOT EXISTS source VARCHAR DEFAULT 'Manual';

ALTER TABLE risks
  ALTER COLUMN user_id DROP NOT NULL;

-- Allow the ingestion API to insert risks without an active user,
-- provided they are tagged with a source other than 'Manual'.
CREATE POLICY "Allow ingest system to insert risks"
  ON risks FOR INSERT
  WITH CHECK (source != 'Manual');

-- Allow everyone to view ingested risks (or scope this appropriately)
CREATE POLICY "Allow users to view ingested risks"
  ON risks FOR SELECT
  USING (source != 'Manual');
