-- Migration: create_planning_drafts
-- Creates the planning_drafts table for Resource Planning module
-- Each draft represents a PM planning session for a date range

CREATE TABLE IF NOT EXISTS planning_drafts (
  id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id              UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_id             UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  created_by_resource    VARCHAR(50) NOT NULL,
  name                   VARCHAR(255) NOT NULL,
  date_from              DATE NOT NULL,
  date_to                DATE NOT NULL,
  status                 VARCHAR(20) NOT NULL DEFAULT 'draft',
  -- Valid statuses: 'draft' | 'locked' | 'publishing' | 'published' | 'error'
  bc_baseline_fetched_at TIMESTAMPTZ,
  published_at           TIMESTAMPTZ,
  publish_summary        JSONB,
  -- { created: number, updated: number, deleted: number, unchanged: number, failed: number, errors: [...] }
  notes                  TEXT,
  created_at             TIMESTAMPTZ DEFAULT NOW(),
  updated_at             TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_planning_drafts_company ON planning_drafts(company_id);
CREATE INDEX IF NOT EXISTS idx_planning_drafts_tenant  ON planning_drafts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_planning_drafts_status  ON planning_drafts(status);
CREATE INDEX IF NOT EXISTS idx_planning_drafts_created_by ON planning_drafts(created_by_resource);
