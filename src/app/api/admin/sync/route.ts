import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { logger } from '@/lib/logger';

/**
 * Admin endpoint to sync all pending entries for a tenant
 * This bypasses user filtering and syncs ALL pending entries
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now();

  try {
    const { tenantId } = await request.json();

    if (!tenantId) {
      return NextResponse.json({ error: 'Tenant ID required' }, { status: 400 });
    }

    logger.info('Admin sync started', { tenantId });

    // Get tenant
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('id', tenantId)
      .single();

    if (tenantError || !tenant) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Check if BC sync is enabled
    if (!tenant.oauth_enabled) {
      return NextResponse.json({
        success: false,
        message: 'Business Central sync not enabled for this tenant'
      }, { status: 400 });
    }

    // Get all companies for this tenant
    const { data: companies, error: companiesError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('tenant_id', tenantId);

    if (companiesError || !companies || companies.length === 0) {
      return NextResponse.json({
        success: false,
        message: 'No companies found for this tenant'
      }, { status: 404 });
    }

    let totalSynced = 0;
    let totalFailed = 0;
    const companyResults: any[] = [];

    // Process each company
    for (const company of companies) {
      // Get ALL pending entries for this company (no user filter)
      const { data: pendingEntries, error: entriesError } = await supabaseAdmin
        .rpc('get_pending_sync_entries', {
          p_company_id: company.id,
          p_resource_no: null  // No user filter - get ALL pending entries
        });

      if (entriesError) {
        logger.error('Error getting pending entries', { companyId: company.id, error: entriesError });
        companyResults.push({
          company_id: company.id,
          company_name: company.name,
          synced: 0,
          failed: 0,
          error: entriesError.message
        });
        continue;
      }

      if (!pendingEntries || pendingEntries.length === 0) {
        companyResults.push({
          company_id: company.id,
          company_name: company.name,
          synced: 0,
          failed: 0,
          message: 'No pending entries'
        });
        continue;
      }

      logger.info('Processing company', {
        companyId: company.id,
        companyName: company.name,
        pendingCount: pendingEntries.length
      });

      // Initialize BC Client
      const bcClient = new BusinessCentralClient(tenant, company);

      let syncedCount = 0;
      let failedCount = 0;
      const errors: string[] = [];

      // Process each entry
      for (const entry of pendingEntries) {
        const batchName = entry.bc_batch_name;

        if (!batchName) {
          logger.error('Entry missing batch name', { entryId: entry.id });

          await supabaseAdmin
            .from('time_entries')
            .update({
              bc_sync_status: 'error',
              bc_last_sync_at: new Date().toISOString()
            })
            .eq('id', entry.id);

          failedCount++;
          errors.push(`Entry ${entry.id}: No batch name`);
          continue;
        }

        try {
          let bcJournalLine;

          if (entry.bc_journal_id) {
            // Update existing
            bcJournalLine = await bcClient.updateJobJournalLine({
              journalTemplateName: 'PROJECT',
              journalBatchName: batchName,
              id: entry.bc_journal_id,
              jobNo: entry.bc_job_id,
              jobTaskNo: entry.bc_task_id,
              type: 'Resource',
              no: entry.resource_no,
              postingDate: entry.date,
              quantity: parseFloat(entry.hours),
              description: entry.description
            });
          } else {
            // Create new
            bcJournalLine = await bcClient.createJobJournalLine({
              journalTemplateName: 'PROJECT',
              journalBatchName: batchName,
              lineNo: 0,
              jobNo: entry.bc_job_id,
              jobTaskNo: entry.bc_task_id,
              type: 'Resource',
              no: entry.resource_no,
              postingDate: entry.date,
              quantity: parseFloat(entry.hours),
              description: entry.description
            });
          }

          // Update local status
          await supabaseAdmin
            .from('time_entries')
            .update({
              bc_sync_status: 'synced',
              bc_journal_id: bcJournalLine.id,
              bc_batch_name: batchName,
              bc_last_sync_at: new Date().toISOString(),
              is_editable: true
            })
            .eq('id', entry.id);

          syncedCount++;

        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          logger.error('Failed to sync entry', { entryId: entry.id, error: errorMessage });

          await supabaseAdmin
            .from('time_entries')
            .update({
              bc_sync_status: 'error',
              bc_last_sync_at: new Date().toISOString()
            })
            .eq('id', entry.id);

          failedCount++;
          errors.push(`Entry ${entry.id}: ${errorMessage}`);
        }
      }

      totalSynced += syncedCount;
      totalFailed += failedCount;

      companyResults.push({
        company_id: company.id,
        company_name: company.name,
        synced: syncedCount,
        failed: failedCount,
        errors: errors.length > 0 ? errors : undefined
      });
    }

    const duration = Date.now() - startTime;

    // Log the admin sync operation
    await supabaseAdmin.from('bc_sync_logs').insert({
      tenant_id: tenantId,
      operation_type: 'admin_sync',
      log_level: totalFailed > 0 ? (totalSynced > 0 ? 'warning' : 'error') : 'success',
      message: `Admin sync completed: ${totalSynced} succeeded, ${totalFailed} failed across ${companies.length} company(ies)`,
      entries_processed: totalSynced + totalFailed,
      entries_succeeded: totalSynced,
      entries_failed: totalFailed,
      duration_ms: duration,
      details: {
        companies: companyResults
      }
    });

    logger.info('Admin sync completed', {
      tenantId,
      totalSynced,
      totalFailed,
      duration
    });

    return NextResponse.json({
      success: true,
      synced: totalSynced,
      failed: totalFailed,
      companies: companyResults,
      duration_ms: duration
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Admin sync failed', { error: errorMessage });

    return NextResponse.json({
      success: false,
      error: 'Sync failed',
      details: errorMessage
    }, { status: 500 });
  }
}
