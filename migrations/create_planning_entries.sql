-- Migration: create_planning_entries
-- Creates the planning_entries table for Resource Planning module
-- Each row = planned hours for a resource/job/task/day within a draft

CREATE TABLE IF NOT EXISTS planning_entries (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  draft_id        UUID NOT NULL REFERENCES planning_drafts(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_id      UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  resource_no     VARCHAR(50) NOT NULL,
  bc_job_id       VARCHAR(50) NOT NULL,
  bc_task_id      VARCHAR(50) NOT NULL,
  planning_date   DATE NOT NULL,
  planned_hours   DECIMAL(8,2) NOT NULL DEFAULT 0,
  description     TEXT,
  publish_status  VARCHAR(20) NOT NULL DEFAULT 'pending',
  -- Valid statuses: 'pending' | 'created' | 'updated' | 'deleted' | 'unchanged' | 'error'
  bc_line_no      INTEGER,         -- lineNo in BC after publish
  bc_system_id    VARCHAR(100),    -- BC systemId for etag lookup
  bc_etag         TEXT,            -- stored after publish for future PATCH/DELETE
  publish_error   TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (draft_id, resource_no, bc_job_id, bc_task_id, planning_date)
);

CREATE INDEX IF NOT EXISTS idx_planning_entries_draft     ON planning_entries(draft_id);
CREATE INDEX IF NOT EXISTS idx_planning_entries_resource  ON planning_entries(resource_no);
CREATE INDEX IF NOT EXISTS idx_planning_entries_date      ON planning_entries(planning_date);
CREATE INDEX IF NOT EXISTS idx_planning_entries_company   ON planning_entries(company_id);
CREATE INDEX IF NOT EXISTS idx_planning_entries_job       ON planning_entries(bc_job_id);
