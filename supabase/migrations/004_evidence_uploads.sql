-- ============================================================
-- FortiGRC — Feature 3: Evidence Documentation Uploads
-- Migration 004: Adjust evidence_documentation for polymorphic
--                entity linking (Risk or Compliance)
-- ============================================================

-- 1. Create an enum for entity types
CREATE TYPE evidence_entity_type AS ENUM ('Risk', 'Compliance');

-- 2. Add the polymorphic columns
ALTER TABLE evidence_documentation
  ADD COLUMN entity_id   UUID                  NOT NULL DEFAULT gen_random_uuid(),
  ADD COLUMN entity_type evidence_entity_type  NOT NULL DEFAULT 'Risk',
  ADD COLUMN file_name   VARCHAR               NOT NULL DEFAULT '';

-- 3. Backfill: copy existing risk_id → entity_id and set entity_type
UPDATE evidence_documentation
  SET entity_id   = COALESCE(risk_id, gen_random_uuid()),
      entity_type = 'Risk',
      file_name   = COALESCE(title, '');

-- 4. Remove the defaults now that backfill is complete
ALTER TABLE evidence_documentation
  ALTER COLUMN entity_id   DROP DEFAULT,
  ALTER COLUMN entity_type DROP DEFAULT,
  ALTER COLUMN file_name   DROP DEFAULT;

-- 5. Drop the old columns that are now superseded
ALTER TABLE evidence_documentation
  DROP COLUMN IF EXISTS risk_id,
  DROP COLUMN IF EXISTS title,
  DROP COLUMN IF EXISTS description;
