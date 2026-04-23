-- ============================================================
-- FortiGRC — Database Security
-- Migration 005: Create audit_logs table
-- ============================================================

CREATE TABLE audit_logs (
  id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID            NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action      VARCHAR         NOT NULL,
  table_name  VARCHAR         NOT NULL,
  record_id   UUID            NOT NULL,
  ip_address  VARCHAR         NOT NULL,
  created_at  TIMESTAMPTZ     DEFAULT now()
);

-- RLS: Only admins/super_admins can read (assuming later RBAC).
-- For now, default to RLS blocked unless explicit policy is added.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- No one can update or delete audit logs
-- (Tamper proofing)
-- No UPDATE or DELETE policies created.
