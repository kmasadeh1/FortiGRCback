-- ============================================================
-- FortiGRC — Feature 2: Compliance Control Mapping
-- Migration 002: Create enum and the `compliance_controls` table
-- ============================================================

-- 1. Custom enum for SELECT framework principles
CREATE TYPE select_principle_enum AS ENUM (
  'Strategic',
  'Enterprise Driven',
  'Livable',
  'Economical',
  'Capability Based',
  'Trustable'
);

-- 2. Compliance controls table, linked to risks via FK
CREATE TABLE compliance_controls (
  id                UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_id           UUID                NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  control_name      VARCHAR             NOT NULL,
  select_principle  select_principle_enum NOT NULL,
  is_compliant      BOOLEAN             NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ         DEFAULT now()
);
