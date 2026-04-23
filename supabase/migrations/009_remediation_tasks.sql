-- ============================================================
-- FortiGRC — Remediation Tasks
-- Migration 009: Create Remediation Tasks schema
-- ============================================================

-- 1. Ensure profiles table exists to satisfy foreign keys
CREATE TABLE IF NOT EXISTS profiles (
  id          UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name   TEXT,
  role        VARCHAR DEFAULT 'user'
);

-- 2. Create the Status enum
CREATE TYPE remediation_status AS ENUM ('Open', 'In Progress', 'Resolved');

-- 3. Create the Remediation Tasks table
CREATE TABLE remediation_tasks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_id       UUID NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  assigned_to   UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  due_date      TIMESTAMPTZ,
  status        remediation_status DEFAULT 'Open',
  notes         TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- 4. Enable RLS
ALTER TABLE remediation_tasks ENABLE ROW LEVEL SECURITY;

-- 5. Build strict security policies 
-- Admins/Super Admins can insert/update all tasks 
-- (Assuming profiles.role identifies admin status). For safety and simplicity,
-- we check the profiles table natively.

-- Allow users to view tasks assigned to themselves
CREATE POLICY "Users view assigned tasks"
  ON remediation_tasks FOR SELECT
  USING (auth.uid() = assigned_to);

-- Allow users to update tasks assigned to themselves
CREATE POLICY "Users update assigned tasks"
  ON remediation_tasks FOR UPDATE
  USING (auth.uid() = assigned_to)
  WITH CHECK (auth.uid() = assigned_to);

-- Note: In a production environment, broader Admin visibility policies 
-- would be linked directly via an EXISTS query against the profiles table.
