-- ============================================================
-- FortiGRC — Security Hardening
-- Migration 003: Add user ownership, RLS, and evidence table
-- ============================================================

-- ============================================================
-- 1. Add user_id ownership columns to existing tables
-- ============================================================

-- NOTE: If you have existing rows, you must first backfill them
-- with a valid user UUID before running this migration.
-- Example:  UPDATE risks SET user_id = '<your-user-uuid>';

ALTER TABLE risks
  ADD COLUMN user_id UUID NOT NULL DEFAULT auth.uid()
  REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE compliance_controls
  ADD COLUMN user_id UUID NOT NULL DEFAULT auth.uid()
  REFERENCES auth.users(id) ON DELETE CASCADE;

-- ============================================================
-- 2. Create the evidence_documentation table
-- ============================================================

CREATE TABLE evidence_documentation (
  id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID            NOT NULL DEFAULT auth.uid()
                              REFERENCES auth.users(id) ON DELETE CASCADE,
  title       VARCHAR         NOT NULL,
  description TEXT,
  file_url    TEXT,
  risk_id     UUID            REFERENCES risks(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ     DEFAULT now()
);

-- ============================================================
-- 3. Enable Row Level Security on ALL tables
-- ============================================================

ALTER TABLE risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_documentation ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 4. RLS Policies — risks
-- ============================================================

CREATE POLICY "Users can view their own risks"
  ON risks FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own risks"
  ON risks FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own risks"
  ON risks FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own risks"
  ON risks FOR DELETE
  USING (auth.uid() = user_id);

-- ============================================================
-- 5. RLS Policies — compliance_controls
-- ============================================================

CREATE POLICY "Users can view their own compliance controls"
  ON compliance_controls FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own compliance controls"
  ON compliance_controls FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own compliance controls"
  ON compliance_controls FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own compliance controls"
  ON compliance_controls FOR DELETE
  USING (auth.uid() = user_id);

-- ============================================================
-- 6. RLS Policies — evidence_documentation
-- ============================================================

CREATE POLICY "Users can view their own evidence"
  ON evidence_documentation FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own evidence"
  ON evidence_documentation FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own evidence"
  ON evidence_documentation FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own evidence"
  ON evidence_documentation FOR DELETE
  USING (auth.uid() = user_id);
