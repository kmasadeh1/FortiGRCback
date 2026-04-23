-- ============================================================
-- FortiGRC — Evidence File Uploads Schema
-- Migration 008: Create evidence table and storage bucket
-- ============================================================

-- 1. Create Evidence Table
CREATE TABLE evidence (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id    UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
  file_name     VARCHAR NOT NULL,
  file_url      TEXT NOT NULL,
  uploaded_by   UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- 2. Enable RLS
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;

-- 3. RLS Policies
-- Admins/Super Admins can insert/select (Simulated basic RLS for authenticated)
CREATE POLICY "Authenticated users can select evidence"
  ON evidence FOR SELECT
  USING (auth.role() = 'authenticated');

CREATE POLICY "Authenticated users can insert evidence"
  ON evidence FOR INSERT
  WITH CHECK (auth.role() = 'authenticated' AND auth.uid() = uploaded_by);

-- ============================================================
-- SUPABASE STORAGE BUCKET CREATION (Note: Must be executed by superuser)
-- ============================================================
INSERT INTO storage.buckets (id, name, public)
VALUES ('fortigrc-evidence', 'fortigrc-evidence', false)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS - allow authenticated users to upload and read
CREATE POLICY "Authenticated can upload evidence files"
  ON storage.objects FOR INSERT 
  WITH CHECK (bucket_id = 'fortigrc-evidence' AND auth.role() = 'authenticated');

CREATE POLICY "Authenticated can read evidence files"
  ON storage.objects FOR SELECT 
  USING (bucket_id = 'fortigrc-evidence' AND auth.role() = 'authenticated');
