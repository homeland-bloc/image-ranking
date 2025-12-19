-- Migration: Add is_pinned column to contests, mergers, and extracts tables
-- Issue #10 Part B: Database columns for pin feature
-- Execute this SQL on your Supabase database

-- Add is_pinned column to contests table
ALTER TABLE contests
ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;

-- Add is_pinned column to mergers table
ALTER TABLE mergers
ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;

-- Add is_pinned column to extracts table
ALTER TABLE extracts
ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;

-- Optional: Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_contests_is_pinned ON contests(is_pinned);
CREATE INDEX IF NOT EXISTS idx_mergers_is_pinned ON mergers(is_pinned);
CREATE INDEX IF NOT EXISTS idx_extracts_is_pinned ON extracts(is_pinned);

-- Verification queries (run after migration)
-- SELECT COUNT(*) FROM contests WHERE is_pinned = TRUE;
-- SELECT COUNT(*) FROM mergers WHERE is_pinned = TRUE;
-- SELECT COUNT(*) FROM extracts WHERE is_pinned = TRUE;
