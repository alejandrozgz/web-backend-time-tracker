-- Add user activity tracking based on time_entries
-- This migration tracks user activity without needing a separate users table
-- We use time_entries.resource_no to identify unique users

-- Create materialized view for user activity (optional, for performance)
-- This aggregates data from time_entries to track last activity per user

-- Create function to get active users statistics based on time_entries
CREATE OR REPLACE FUNCTION get_active_users_stats(p_days INTEGER DEFAULT 30)
RETURNS TABLE (
  tenant_id UUID,
  tenant_name VARCHAR,
  company_id UUID,
  company_name VARCHAR,
  resource_no VARCHAR,
  last_activity TIMESTAMPTZ,
  days_since_activity INTEGER,
  total_entries INTEGER,
  total_hours DECIMAL
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT
    t.id as tenant_id,
    t.name as tenant_name,
    c.id as company_id,
    c.name as company_name,
    te.resource_no,
    MAX(te.last_modified_at) as last_activity,
    EXTRACT(DAY FROM (NOW() - MAX(te.last_modified_at)))::INTEGER as days_since_activity,
    COUNT(te.id)::INTEGER as total_entries,
    SUM(te.hours)::DECIMAL as total_hours
  FROM time_entries te
  INNER JOIN companies c ON te.company_id = c.id
  INNER JOIN tenants t ON c.tenant_id = t.id
  WHERE te.resource_no IS NOT NULL
    AND (
      te.last_modified_at >= NOW() - (p_days || ' days')::INTERVAL
      OR te.created_at >= NOW() - (p_days || ' days')::INTERVAL
    )
  GROUP BY t.id, t.name, c.id, c.name, te.resource_no
  ORDER BY t.name, c.name, last_activity DESC;
END;
$$;

-- Create function to get active users summary by tenant
CREATE OR REPLACE FUNCTION get_active_users_summary(p_days INTEGER DEFAULT 30)
RETURNS TABLE (
  tenant_id UUID,
  tenant_name VARCHAR,
  total_users INTEGER,
  active_users INTEGER,
  total_entries INTEGER,
  total_hours DECIMAL
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  WITH user_activity AS (
    SELECT
      c.tenant_id,
      te.resource_no,
      MAX(te.last_modified_at) as last_activity,
      COUNT(te.id) as entry_count,
      SUM(te.hours) as hour_count
    FROM time_entries te
    INNER JOIN companies c ON te.company_id = c.id
    WHERE te.resource_no IS NOT NULL
    GROUP BY c.tenant_id, te.resource_no
  )
  SELECT
    t.id as tenant_id,
    t.name as tenant_name,
    COUNT(DISTINCT ua.resource_no)::INTEGER as total_users,
    COUNT(DISTINCT CASE
      WHEN ua.last_activity >= NOW() - (p_days || ' days')::INTERVAL
      THEN ua.resource_no
    END)::INTEGER as active_users,
    SUM(ua.entry_count)::INTEGER as total_entries,
    SUM(ua.hour_count)::DECIMAL as total_hours
  FROM tenants t
  LEFT JOIN user_activity ua ON ua.tenant_id = t.id
  WHERE t.is_active = true
  GROUP BY t.id, t.name
  ORDER BY t.name;
END;
$$;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION get_active_users_stats(INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION get_active_users_summary(INTEGER) TO service_role;

-- Add comments
COMMENT ON FUNCTION get_active_users_stats(INTEGER) IS
'Returns detailed list of users (by resource_no) who have created or modified time entries within the specified number of days. Default is 30 days. Activity is tracked via time_entries table.';

COMMENT ON FUNCTION get_active_users_summary(INTEGER) IS
'Returns summary statistics of active users (by resource_no) grouped by tenant for the specified number of days. Default is 30 days. Activity is tracked via time_entries table.';
