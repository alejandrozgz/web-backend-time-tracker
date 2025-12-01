import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { logger } from '@/lib/logger';

/**
 * Refresh approval status and comments from BC for synced time entries
 * GET /api/[tenant]/sync/refresh-status?companyId=xxx
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  const startTime = Date.now();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get('companyId');
  const { tenant: tenantSlug } = await params;

  try {
    logger.info('Refresh status from BC started', { tenantSlug, companyId });

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // Extract resourceNo from JWT token to filter by user
    const authHeader = request.headers.get('authorization');
    let resourceNo: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo;
        logger.info('Refresh status requested by user', { resourceNo });
      } catch (e) {
        logger.warn('Could not decode token for user filtering', { error: e });
      }
    }

    // Get tenant and company
    const [tenantResult, companyResult] = await Promise.all([
      supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single(),
      supabaseAdmin.from('companies').select('*').eq('id', companyId).single()
    ]);

    const { data: tenant, error: tenantError } = tenantResult;
    const { data: company, error: companyError } = companyResult;

    if (tenantError || !tenant) {
      throw new Error('Tenant not found');
    }
    if (companyError || !company) {
      throw new Error('Company not found');
    }

    // Check if BC sync is enabled
    if (!tenant.oauth_enabled) {
      return NextResponse.json({
        success: false,
        updated_entries: 0,
        message: 'Business Central sync not enabled for this tenant'
      });
    }

    // Get synced entries that have bc_journal_id (only synced entries can have approval status)
    let query = supabaseAdmin
      .from('time_entries')
      .select('id, bc_journal_id, approval_status, bc_comments')
      .eq('company_id', companyId)
      .eq('bc_sync_status', 'synced')
      .not('bc_journal_id', 'is', null);

    // Filter by user if resourceNo is available
    if (resourceNo) {
      const { data: resource } = await supabaseAdmin
        .from('resources')
        .select('id')
        .eq('resource_no', resourceNo)
        .eq('company_id', companyId)
        .single();

      if (resource) {
        query = query.eq('resource_id', resource.id);
      }
    }

    const { data: syncedEntries, error: entriesError } = await query;

    if (entriesError) throw entriesError;

    if (!syncedEntries || syncedEntries.length === 0) {
      logger.info('No synced entries to refresh', { companyId, resourceNo });
      return NextResponse.json({
        success: true,
        updated_entries: 0,
        message: 'No synced entries to refresh'
      });
    }

    logger.info('Synced entries found for refresh', { count: syncedEntries.length, companyId });

    // Initialize BC Client
    const bcClient = new BusinessCentralClient(tenant, company);

    // Get all journal IDs
    const journalIds = syncedEntries
      .map(e => e.bc_journal_id)
      .filter((id): id is string => id !== null);

    // Fetch statuses from BC in batch
    const bcStatuses = await bcClient.getJobJournalLinesStatus(journalIds);

    let updatedCount = 0;
    const updates: any[] = [];

    // Check each entry and update if status changed
    for (const entry of syncedEntries) {
      if (!entry.bc_journal_id) continue;

      const bcStatus = bcStatuses.get(entry.bc_journal_id);

      if (bcStatus) {
        // Check if anything changed
        const statusChanged = entry.approval_status !== bcStatus.approvalStatus;
        const commentsChanged = entry.bc_comments !== bcStatus.comments;

        if (statusChanged || commentsChanged) {
          updates.push({
            id: entry.id,
            bc_journal_id: entry.bc_journal_id,
            old_status: entry.approval_status,
            new_status: bcStatus.approvalStatus,
            old_comments: entry.bc_comments,
            new_comments: bcStatus.comments
          });

          // Update in database
          await supabaseAdmin
            .from('time_entries')
            .update({
              approval_status: bcStatus.approvalStatus.toLowerCase(),
              bc_comments: bcStatus.comments
            })
            .eq('id', entry.id);

          updatedCount++;
        }
      }
    }

    const duration = Date.now() - startTime;

    logger.info('Refresh status completed', {
      checked: syncedEntries.length,
      updated: updatedCount,
      durationMs: duration
    });

    // Log the refresh operation
    await supabaseAdmin.from('bc_sync_logs').insert({
      tenant_id: tenant.id,
      company_id: companyId,
      operation_type: 'refresh_status',
      log_level: 'info',
      message: `Refreshed approval status: ${updatedCount} entries updated out of ${syncedEntries.length} checked`,
      entries_processed: syncedEntries.length,
      entries_succeeded: updatedCount,
      entries_failed: 0,
      duration_ms: duration,
      details: {
        updates: updates.length > 0 ? updates : undefined
      }
    });

    return NextResponse.json({
      success: true,
      checked_entries: syncedEntries.length,
      updated_entries: updatedCount,
      updates: updates,
      message: `Checked ${syncedEntries.length} entries, updated ${updatedCount}`
    });

  } catch (error) {
    logger.error('Refresh status failed', { error, tenantSlug, companyId });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const duration = Date.now() - startTime;

    // Try to log the error
    if (tenantSlug && companyId) {
      try {
        const { data: tenant } = await supabaseAdmin
          .from('tenants')
          .select('id')
          .eq('slug', tenantSlug)
          .single();

        if (tenant) {
          await supabaseAdmin.from('bc_sync_logs').insert({
            tenant_id: tenant.id,
            company_id: companyId,
            operation_type: 'refresh_status',
            log_level: 'error',
            message: 'Refresh status operation failed',
            bc_error_message: errorMessage,
            duration_ms: duration,
            entries_processed: 0,
            entries_succeeded: 0,
            entries_failed: 0
          });
        }
      } catch (logError) {
        console.error('Failed to log error:', logError);
      }
    }

    return NextResponse.json({
      success: false,
      checked_entries: 0,
      updated_entries: 0,
      error: 'Refresh failed',
      details: errorMessage
    }, { status: 500 });
  }
}
