-- Migration: Create pinned_items table
-- Description: Allows admins to pin contests, mergers, and extracts to the top of lists
-- Author: Claude
-- Date: 2025-12-29

-- Create pinned_items table
CREATE TABLE IF NOT EXISTS pinned_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_type TEXT NOT NULL CHECK (item_type IN ('contest', 'merger', 'extract')),
    item_id UUID NOT NULL,
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pinned_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Ensure unique pinning (one pin per item)
    UNIQUE(item_type, item_id)
);

-- Create indexes for better query performance
CREATE INDEX idx_pinned_items_type_id ON pinned_items(item_type, item_id);
CREATE INDEX idx_pinned_items_pinned_at ON pinned_items(pinned_at DESC);
CREATE INDEX idx_pinned_items_pinned_by ON pinned_items(pinned_by);

-- Add RLS (Row Level Security) policies
ALTER TABLE pinned_items ENABLE ROW LEVEL SECURITY;

-- Allow anyone to view pinned items
CREATE POLICY "Pinned items are viewable by everyone"
    ON pinned_items
    FOR SELECT
    USING (true);

-- Only allow specific admin to create/delete pins
-- Note: Replace 'ADMIN_DISCORD_ID' with your actual admin Discord ID
CREATE POLICY "Only admin can create pins"
    ON pinned_items
    FOR INSERT
    WITH CHECK (auth.uid() = 'ADMIN_DISCORD_ID' OR pinned_by = 'ADMIN_DISCORD_ID');

CREATE POLICY "Only admin can delete pins"
    ON pinned_items
    FOR DELETE
    USING (auth.uid() = 'ADMIN_DISCORD_ID' OR pinned_by = 'ADMIN_DISCORD_ID');

-- Grant permissions
GRANT SELECT ON pinned_items TO anon, authenticated;
GRANT INSERT, DELETE ON pinned_items TO authenticated;

-- Add helpful comments
COMMENT ON TABLE pinned_items IS 'Stores pinned items (contests, mergers, extracts) for display at top of lists';
COMMENT ON COLUMN pinned_items.item_type IS 'Type of item being pinned: contest, merger, or extract';
COMMENT ON COLUMN pinned_items.item_id IS 'UUID of the pinned item (references contests.id, mergers.id, or extracts.id)';
COMMENT ON COLUMN pinned_items.pinned_at IS 'Timestamp when item was pinned';
COMMENT ON COLUMN pinned_items.pinned_by IS 'Discord ID of admin who pinned the item';
