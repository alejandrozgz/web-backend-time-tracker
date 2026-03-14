-- Migration: add_capacity_to_resources
-- Adds daily_capacity_hours to the resources table
-- Used by the capacity view to determine overload thresholds
-- Role is NOT stored here — it comes from BC field isPlanningManager at login time

ALTER TABLE resources
  ADD COLUMN IF NOT EXISTS daily_capacity_hours DECIMAL(4,2) DEFAULT 8.0;
