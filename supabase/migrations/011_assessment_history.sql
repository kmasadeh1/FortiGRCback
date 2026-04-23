-- Migration: 011_assessment_history.sql
-- Creates the assessment_history table for the Assessment Questionnaire feature

CREATE TABLE IF NOT EXISTS public.assessment_history (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    title           TEXT NOT NULL,
    score           TEXT,                            -- e.g. "80%"
    completed_by    UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    completed_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Index for retrieving the most recent audits first
CREATE INDEX IF NOT EXISTS idx_assessment_history_completed_at
    ON public.assessment_history(completed_at DESC);

-- RLS
ALTER TABLE public.assessment_history ENABLE ROW LEVEL SECURITY;

-- Authenticated users can read all history
CREATE POLICY "Allow read for authenticated users"
    ON public.assessment_history FOR SELECT
    USING (auth.role() = 'authenticated');

-- Authenticated users can insert new assessment records
CREATE POLICY "Allow insert for authenticated users"
    ON public.assessment_history FOR INSERT
    WITH CHECK (auth.role() = 'authenticated');
