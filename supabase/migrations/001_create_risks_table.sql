-- ============================================================
-- FortiGRC — Feature 1: Quantitative Risk Management
-- Migration 001: Create enums and the `risks` table
-- ============================================================

-- 1. Custom enum for JNCSF capability domains
CREATE TYPE jncsf_capability_enum AS ENUM (
  'Architecture & Portfolio',
  'Development',
  'Delivery',
  'Operations',
  'Fundamental Capabilities',
  'National Cyber Responsibility'
);

-- 2. Custom enum for risk lifecycle status
CREATE TYPE risk_status_enum AS ENUM (
  'Open',
  'In Progress',
  'Mitigated'
);

-- 3. Risks table with auto-calculated quantitative score
CREATE TABLE risks (
  id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  title               VARCHAR         NOT NULL,
  jncsf_capability    jncsf_capability_enum NOT NULL,
  event_frequency     NUMERIC(10, 4)  NOT NULL,
  event_magnitude     NUMERIC(15, 2)  NOT NULL,
  quantitative_score  NUMERIC(15, 2)  GENERATED ALWAYS AS (event_frequency * event_magnitude) STORED,
  status              risk_status_enum DEFAULT 'Open',
  created_at          TIMESTAMPTZ     DEFAULT now()
);
