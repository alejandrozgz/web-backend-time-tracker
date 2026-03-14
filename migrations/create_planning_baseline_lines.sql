-- Migration: create_planning_baseline_lines
-- Snapshot of BC jobPlanningLines taken when a draft is created
-- Used as reference for diff computation (local vs BC baseline)
-- Does NOT change when PM edits planning_entries

CREATE TABLE IF NOT EXISTS planning_baseline_lines (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  draft_id        UUID NOT NULL REFERENCES planning_drafts(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_id      UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  resource_no     VARCHAR(50) NOT NULL,
  bc_job_id       VARCHAR(50) NOT NULL,
  bc_task_id      VARCHAR(50) NOT NULL,
  planning_date   DATE NOT NULL,
  quantity        DECIMAL(8,2) NOT NULL,
  description     TEXT,
  bc_line_no      INTEGER NOT NULL,   -- lineNo in BC (required for PATCH/DELETE)
  bc_system_id    VARCHAR(100),       -- BC systemId
  bc_etag         TEXT,               -- ETag at snapshot time (used for publish PATCH/DELETE)
  fetched_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (draft_id, resource_no, bc_job_id, bc_task_id, planning_date)
);

CREATE INDEX IF NOT EXISTS idx_baseline_lines_draft    ON planning_baseline_lines(draft_id);
CREATE INDEX IF NOT EXISTS idx_baseline_lines_resource ON planning_baseline_lines(resource_no);
CREATE INDEX IF NOT EXISTS idx_baseline_lines_date     ON planning_baseline_lines(planning_date);
CREATE INDEX IF NOT EXISTS idx_baseline_lines_company  ON planning_baseline_lines(company_id);
