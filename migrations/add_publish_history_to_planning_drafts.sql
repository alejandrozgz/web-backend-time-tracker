ALTER TABLE planning_drafts ADD COLUMN IF NOT EXISTS publish_history JSONB DEFAULT '[]'::jsonb;
