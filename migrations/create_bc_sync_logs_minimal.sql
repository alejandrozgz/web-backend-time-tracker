-- Minimal migration to create bc_sync_logs table
-- Execute this in Supabase SQL Editor if the table doesn't exist

-- Create ENUMs if they don't exist
DO $$ BEGIN
  CREATE TYPE sync_log_level AS ENUM ('info', 'warning', 'error', 'success');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE sync_operation_type AS ENUM ('sync_to_bc', 'post_batch', 'fetch_from_bc', 'retry');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- Create bc_sync_logs table
CREATE TABLE IF NOT EXISTS bc_sync_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  operation_type sync_operation_type NOT NULL,
  batch_name VARCHAR(50),
  batch_id UUID REFERENCES bc_sync_batches(id) ON DELETE SET NULL,
  time_entry_id UUID REFERENCES time_entries(id) ON DELETE SET NULL,
  log_level sync_log_level NOT NULL,
  message TEXT NOT NULL,
  details JSONB,
  entries_processed INT,
  entries_succeeded INT,
  entries_failed INT,
  total_hours DECIMAL(10,2),
  duration_ms INT,
  user_id UUID,
  resource_no VARCHAR(50),
  bc_journal_id VARCHAR(50),
  bc_error_code VARCHAR(50),
  bc_error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_company_id ON bc_sync_logs(company_id);
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_tenant_id ON bc_sync_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_created_at ON bc_sync_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_operation_type ON bc_sync_logs(operation_type);
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_log_level ON bc_sync_logs(log_level);
CREATE INDEX IF NOT EXISTS idx_bc_sync_logs_batch_id ON bc_sync_logs(batch_id);

-- Enable RLS
ALTER TABLE bc_sync_logs ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
CREATE POLICY "Allow service role full access to bc_sync_logs"
  ON bc_sync_logs FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Allow authenticated users to read their company logs"
  ON bc_sync_logs FOR SELECT
  TO authenticated
  USING (
    company_id IN (
      SELECT id FROM companies
      WHERE tenant_id IN (SELECT id FROM tenants WHERE is_active = true)
    )
  );
