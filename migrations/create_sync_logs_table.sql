-- =====================================================
-- Business Central Sync Logs Table
-- =====================================================
-- This table stores detailed logs of all BC synchronization operations
-- including individual entry sync attempts, batch operations, and errors

-- Create enum for log levels
CREATE TYPE sync_log_level AS ENUM ('info', 'warning', 'error', 'success');

-- Create enum for sync operation types
CREATE TYPE sync_operation_type AS ENUM ('sync_to_bc', 'post_batch', 'fetch_from_bc', 'retry');

-- Create the sync logs table
CREATE TABLE IF NOT EXISTS bc_sync_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,

  -- Operation details
  operation_type sync_operation_type NOT NULL,
  batch_name VARCHAR(50),
  batch_id UUID REFERENCES bc_sync_batches(id) ON DELETE SET NULL,

  -- Entry details (if applicable)
  time_entry_id UUID REFERENCES time_entries(id) ON DELETE SET NULL,

  -- Log details
  log_level sync_log_level NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  details JSONB, -- Additional structured data (errors, BC response, etc.)

  -- Metrics
  entries_processed INT,
  entries_succeeded INT,
  entries_failed INT,
  total_hours DECIMAL(10,2),
  duration_ms INT, -- Operation duration in milliseconds

  -- User context
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  resource_no VARCHAR(50),

  -- BC context
  bc_journal_id VARCHAR(100), -- BC Journal Line ID if applicable
  bc_error_code VARCHAR(50),
  bc_error_message TEXT,

  -- Timestamps
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Indexes for common queries
  CONSTRAINT valid_entries_count CHECK (
    entries_processed IS NULL OR
    (entries_succeeded IS NOT NULL AND entries_failed IS NOT NULL AND
     entries_processed = entries_succeeded + entries_failed)
  )
);

-- Create indexes for performance
CREATE INDEX idx_bc_sync_logs_tenant ON bc_sync_logs(tenant_id);
CREATE INDEX idx_bc_sync_logs_company ON bc_sync_logs(company_id);
CREATE INDEX idx_bc_sync_logs_created_at ON bc_sync_logs(created_at DESC);
CREATE INDEX idx_bc_sync_logs_operation ON bc_sync_logs(operation_type);
CREATE INDEX idx_bc_sync_logs_level ON bc_sync_logs(log_level);
CREATE INDEX idx_bc_sync_logs_batch ON bc_sync_logs(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX idx_bc_sync_logs_entry ON bc_sync_logs(time_entry_id) WHERE time_entry_id IS NOT NULL;
CREATE INDEX idx_bc_sync_logs_user ON bc_sync_logs(user_id) WHERE user_id IS NOT NULL;

-- Create a composite index for common filtering
CREATE INDEX idx_bc_sync_logs_company_date ON bc_sync_logs(company_id, created_at DESC);
CREATE INDEX idx_bc_sync_logs_batch_name ON bc_sync_logs(batch_name) WHERE batch_name IS NOT NULL;

-- Add comments for documentation
COMMENT ON TABLE bc_sync_logs IS 'Detailed logs of all Business Central synchronization operations';
COMMENT ON COLUMN bc_sync_logs.operation_type IS 'Type of sync operation performed';
COMMENT ON COLUMN bc_sync_logs.log_level IS 'Severity level of the log entry';
COMMENT ON COLUMN bc_sync_logs.details IS 'Additional structured data in JSON format';
COMMENT ON COLUMN bc_sync_logs.duration_ms IS 'Operation duration in milliseconds';
COMMENT ON COLUMN bc_sync_logs.bc_error_code IS 'Error code returned by Business Central API';

-- =====================================================
-- Helper Functions
-- =====================================================

-- Function to get sync logs with filters
CREATE OR REPLACE FUNCTION get_sync_logs(
  p_company_id UUID,
  p_operation_type sync_operation_type DEFAULT NULL,
  p_log_level sync_log_level DEFAULT NULL,
  p_date_from TIMESTAMPTZ DEFAULT NULL,
  p_date_to TIMESTAMPTZ DEFAULT NULL,
  p_limit INT DEFAULT 100,
  p_offset INT DEFAULT 0
)
RETURNS TABLE (
  id UUID,
  tenant_id UUID,
  company_id UUID,
  operation_type sync_operation_type,
  batch_name VARCHAR,
  batch_id UUID,
  time_entry_id UUID,
  log_level sync_log_level,
  message TEXT,
  details JSONB,
  entries_processed INT,
  entries_succeeded INT,
  entries_failed INT,
  total_hours DECIMAL,
  duration_ms INT,
  user_id UUID,
  resource_no VARCHAR,
  bc_journal_id VARCHAR,
  bc_error_code VARCHAR,
  bc_error_message TEXT,
  created_at TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    l.id,
    l.tenant_id,
    l.company_id,
    l.operation_type,
    l.batch_name,
    l.batch_id,
    l.time_entry_id,
    l.log_level,
    l.message,
    l.details,
    l.entries_processed,
    l.entries_succeeded,
    l.entries_failed,
    l.total_hours,
    l.duration_ms,
    l.user_id,
    l.resource_no,
    l.bc_journal_id,
    l.bc_error_code,
    l.bc_error_message,
    l.created_at
  FROM bc_sync_logs l
  WHERE l.company_id = p_company_id
    AND (p_operation_type IS NULL OR l.operation_type = p_operation_type)
    AND (p_log_level IS NULL OR l.log_level = p_log_level)
    AND (p_date_from IS NULL OR l.created_at >= p_date_from)
    AND (p_date_to IS NULL OR l.created_at <= p_date_to)
  ORDER BY l.created_at DESC
  LIMIT p_limit
  OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;

-- Function to get sync statistics
CREATE OR REPLACE FUNCTION get_sync_statistics(
  p_company_id UUID,
  p_date_from TIMESTAMPTZ DEFAULT NOW() - INTERVAL '30 days',
  p_date_to TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
  total_operations INT,
  successful_operations INT,
  failed_operations INT,
  total_entries_processed INT,
  total_entries_succeeded INT,
  total_entries_failed INT,
  total_hours DECIMAL,
  avg_duration_ms DECIMAL,
  last_sync_at TIMESTAMPTZ,
  errors_by_code JSONB
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*)::INT AS total_operations,
    COUNT(*) FILTER (WHERE log_level = 'success')::INT AS successful_operations,
    COUNT(*) FILTER (WHERE log_level = 'error')::INT AS failed_operations,
    COALESCE(SUM(entries_processed), 0)::INT AS total_entries_processed,
    COALESCE(SUM(entries_succeeded), 0)::INT AS total_entries_succeeded,
    COALESCE(SUM(entries_failed), 0)::INT AS total_entries_failed,
    COALESCE(SUM(total_hours), 0)::DECIMAL AS total_hours,
    COALESCE(AVG(duration_ms), 0)::DECIMAL AS avg_duration_ms,
    MAX(created_at) AS last_sync_at,
    COALESCE(
      jsonb_object_agg(bc_error_code, error_count) FILTER (WHERE bc_error_code IS NOT NULL),
      '{}'::JSONB
    ) AS errors_by_code
  FROM bc_sync_logs
  LEFT JOIN LATERAL (
    SELECT bc_error_code, COUNT(*)::INT as error_count
    FROM bc_sync_logs l2
    WHERE l2.bc_error_code IS NOT NULL
      AND l2.company_id = p_company_id
      AND l2.created_at >= p_date_from
      AND l2.created_at <= p_date_to
    GROUP BY bc_error_code
  ) error_counts ON true
  WHERE company_id = p_company_id
    AND created_at >= p_date_from
    AND created_at <= p_date_to;
END;
$$ LANGUAGE plpgsql;

-- Function to get recent sync activity (for dashboard)
CREATE OR REPLACE FUNCTION get_recent_sync_activity(
  p_company_id UUID,
  p_hours INT DEFAULT 24
)
RETURNS TABLE (
  hour_start TIMESTAMPTZ,
  total_syncs INT,
  successful_syncs INT,
  failed_syncs INT,
  entries_synced INT,
  hours_synced DECIMAL
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    date_trunc('hour', created_at) AS hour_start,
    COUNT(*)::INT AS total_syncs,
    COUNT(*) FILTER (WHERE log_level = 'success')::INT AS successful_syncs,
    COUNT(*) FILTER (WHERE log_level = 'error')::INT AS failed_syncs,
    COALESCE(SUM(entries_succeeded), 0)::INT AS entries_synced,
    COALESCE(SUM(total_hours), 0)::DECIMAL AS hours_synced
  FROM bc_sync_logs
  WHERE company_id = p_company_id
    AND created_at >= NOW() - (p_hours || ' hours')::INTERVAL
    AND operation_type = 'sync_to_bc'
  GROUP BY date_trunc('hour', created_at)
  ORDER BY hour_start DESC;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- Row Level Security (RLS) Policies
-- =====================================================

-- Enable RLS
ALTER TABLE bc_sync_logs ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view logs for their tenant
CREATE POLICY "Users can view sync logs for their tenant"
  ON bc_sync_logs FOR SELECT
  USING (
    tenant_id IN (
      SELECT tenant_id FROM users WHERE id = auth.uid()
    )
  );

-- Policy: Service role has full access (for API routes)
CREATE POLICY "Service role has full access to sync logs"
  ON bc_sync_logs FOR ALL
  USING (auth.jwt() ->> 'role' = 'service_role');

-- Grant necessary permissions
GRANT SELECT ON bc_sync_logs TO authenticated;
GRANT ALL ON bc_sync_logs TO service_role;
GRANT EXECUTE ON FUNCTION get_sync_logs TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION get_sync_statistics TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION get_recent_sync_activity TO authenticated, service_role;
