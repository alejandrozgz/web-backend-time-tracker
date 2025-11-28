import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/dashboard - Get admin dashboard statistics
async function handler(request: NextRequest) {
  try {
    // Run all queries in parallel
    const [
      tenantsResult,
      companiesResult,
      timeEntriesResult,
      syncLogsResult
    ] = await Promise.all([
      // Tenants stats
      supabaseAdmin
        .from('tenants')
        .select('id, is_active', { count: 'exact' }),

      // Companies stats
      supabaseAdmin
        .from('companies')
        .select('id', { count: 'exact' }),

      // Time entries stats (includes resource_no for user counting)
      supabaseAdmin
        .from('time_entries')
        .select('id, hours, bc_sync_status, resource_no, last_modified_at', { count: 'exact' }),

      // Recent sync logs
      supabaseAdmin
        .from('bc_sync_logs')
        .select('id, log_level, created_at')
        .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
    ]);

    // Process tenants
    const tenants = tenantsResult.data || [];
    const totalTenants = tenantsResult.count || 0;
    const activeTenants = tenants.filter(t => t.is_active).length;

    // Process time entries
    const timeEntries = timeEntriesResult.data || [];
    const totalTimeEntries = timeEntriesResult.count || 0;
    const totalHoursTracked = timeEntries.reduce((sum, entry) => sum + (parseFloat(entry.hours as any) || 0), 0);

    // Count unique users from time entries
    const uniqueResourceNos = new Set(
      timeEntries
        .filter(e => e.resource_no)
        .map(e => e.resource_no)
    );
    const totalUsers = uniqueResourceNos.size;

    // Count active users (with activity in last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const activeResourceNos = new Set(
      timeEntries
        .filter(e => e.resource_no && e.last_modified_at >= thirtyDaysAgo)
        .map(e => e.resource_no)
    );
    const activeUsers = activeResourceNos.size;

    // Count entries by status (new simplified schema)
    const entriesByStatus = {
      not_synced: timeEntries.filter(e => e.bc_sync_status === 'not_synced').length,
      synced: timeEntries.filter(e => e.bc_sync_status === 'synced').length,
      error: timeEntries.filter(e => e.bc_sync_status === 'error').length,
      // Legacy status counts (should be 0 after cleanup migration)
      other: timeEntries.filter(e =>
        e.bc_sync_status &&
        !['not_synced', 'synced', 'error'].includes(e.bc_sync_status)
      ).length
    };

    // Process sync logs
    const syncLogs = syncLogsResult.data || [];
    const recentSyncs = syncLogs.filter(log => log.log_level === 'success').length;
    const failedSyncs = syncLogs.filter(log => log.log_level === 'error').length;

    const stats = {
      total_tenants: totalTenants,
      active_tenants: activeTenants,
      total_companies: companiesResult.count || 0,
      total_users: totalUsers,
      active_users: activeUsers,
      total_time_entries: totalTimeEntries,
      total_hours_tracked: Math.round(totalHoursTracked * 100) / 100,
      entries_by_status: entriesByStatus,
      recent_syncs: recentSyncs,
      failed_syncs: failedSyncs
    };

    return NextResponse.json(stats);

  } catch (error) {
    console.error('Error fetching admin dashboard stats:', error);
    return NextResponse.json(
      { error: 'Failed to fetch dashboard statistics', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(handler);
