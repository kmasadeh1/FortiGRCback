-- Migration: 010_risk_exceptions.sql
-- Creates the risk_exceptions table for the Waiver / Exception Management feature

CREATE TABLE IF NOT EXISTS public.risk_exceptions (
    id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    risk_id     UUID NOT NULL REFERENCES public.risks(id) ON DELETE CASCADE,
    justification   TEXT NOT NULL,
    expiration  DATE NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Pending'
                    CHECK (status IN ('Pending', 'Approved', 'Denied')),
    requested_by    UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    reviewed_by     UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast lookups by risk
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_risk_id ON public.risk_exceptions(risk_id);

-- Index to quickly find all pending waivers
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_status ON public.risk_exceptions(status);

-- RLS: enable row-level security
ALTER TABLE public.risk_exceptions ENABLE ROW LEVEL SECURITY;

-- Authenticated users can read all exceptions
CREATE POLICY "Allow read for authenticated users"
    ON public.risk_exceptions FOR SELECT
    USING (auth.role() = 'authenticated');

-- Any authenticated user can insert (request a waiver)
CREATE POLICY "Allow insert for authenticated users"
    ON public.risk_exceptions FOR INSERT
    WITH CHECK (auth.role() = 'authenticated');

-- Only the API (service role) updates status (Approve / Deny) — enforced at API layer
CREATE POLICY "Allow update for service role"
    ON public.risk_exceptions FOR UPDATE
    USING (auth.role() = 'service_role');
