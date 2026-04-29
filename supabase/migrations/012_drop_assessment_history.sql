-- ============================================================
-- FortiGRC — Cleanup
-- Migration 012: Drop assessment_history table (feature removed)
--
-- Reverses migration 011_assessment_history.sql in the correct
-- dependency order:
--   1. Drop RLS policies (must be dropped before the table)
--   2. Drop index
--   3. Drop table
-- ============================================================

-- 1. Remove RLS policies
DROP POLICY IF EXISTS "Allow read for authenticated users"  ON public.assessment_history;
DROP POLICY IF EXISTS "Allow insert for authenticated users" ON public.assessment_history;

-- 2. Remove index (dropped automatically with the table, but explicit is safer)
DROP INDEX IF EXISTS public.idx_assessment_history_completed_at;

-- 3. Drop the table — CASCADE removes any remaining dependent objects
DROP TABLE IF EXISTS public.assessment_history CASCADE;
