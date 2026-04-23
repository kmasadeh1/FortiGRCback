-- ============================================================
-- FortiGRC — Automated Risk Generation from Assessments
-- Migration 009: Add description column to risks table
-- ============================================================

ALTER TABLE risks
  ADD COLUMN IF NOT EXISTS description TEXT;
