-- ============================================================
-- FortiGRC — JNCF Framework Mapping
-- Migration 006: Create JNCF Domains and Controls
-- ============================================================

-- 1. Create Domains Table
CREATE TABLE jncf_domains (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_code   VARCHAR NOT NULL UNIQUE,
  title         VARCHAR NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- 2. Create Controls Table
CREATE TABLE jncf_controls (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id     UUID NOT NULL REFERENCES jncf_domains(id) ON DELETE CASCADE,
  control_code  VARCHAR NOT NULL UNIQUE,
  description   TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- 3. Add mapping to compliance_controls
ALTER TABLE compliance_controls
  ADD COLUMN jncf_mapping_id UUID REFERENCES jncf_controls(id) ON DELETE SET NULL;

-- 4. Enable RLS
ALTER TABLE jncf_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE jncf_controls ENABLE ROW LEVEL SECURITY;

-- 5. Create basic SELECT policies for authenticated users
CREATE POLICY "Authenticated users can view JNCF domains"
  ON jncf_domains FOR SELECT
  USING (auth.role() = 'authenticated');

CREATE POLICY "Authenticated users can view JNCF controls"
  ON jncf_controls FOR SELECT
  USING (auth.role() = 'authenticated');
