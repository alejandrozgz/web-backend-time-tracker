import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { logger } from '@/lib/logger';

/**
 * Sync Status States:
 * - 'not_synced': Not synced to BC yet (new entry) → sync to BC → 'synced'
 * - 'synced': Synced to BC as editable draft (can be edited/deleted in BC)
 * - 'error': Sync failed, needs retry → retry sync → 'synced'
 */

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  const startTime = Date.now();

  // Parse these outside try block so they're available in catch
  const { companyId } = await request.json();
  const { tenant: tenantSlug } = await params;

  try {

    logger.info('Sync to BC started', { tenantSlug, companyId });

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // 🔑 Extract resourceNo from JWT token to filter sync by user
    const authHeader = request.headers.get('authorization');
    let resourceNo: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo;
        logger.info('Sync requested by user', { resourceNo });
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
      const duration = Date.now() - startTime;

      // Log the failed attempt
      await supabaseAdmin.from('bc_sync_logs').insert({
        tenant_id: tenant.id,
        company_id: companyId,
        operation_type: 'sync_to_bc',
        log_level: 'warning',
        message: 'Business Central sync not enabled for this tenant',
        duration_ms: duration,
        entries_processed: 0,
        entries_succeeded: 0,
        entries_failed: 0
      });

      return NextResponse.json({
        success: false,
        synced_entries: 0,
        failed_entries: 0,
        message: 'Business Central sync not enabled for this tenant'
      });
    }

    // 📊 Get pending entries (filtered by user's resourceNo)
    const { data: pendingEntries, error: entriesError } = await supabaseAdmin
      .rpc('get_pending_sync_entries', {
        p_company_id: companyId,
        p_resource_no: resourceNo  // 🔑 Filter by current user
      });

    if (entriesError) throw entriesError;

    if (!pendingEntries || pendingEntries.length === 0) {
      const duration = Date.now() - startTime;

      // Log no entries to sync
      await supabaseAdmin.from('bc_sync_logs').insert({
        tenant_id: tenant.id,
        company_id: companyId,
        operation_type: 'sync_to_bc',
        log_level: 'info',
        message: resourceNo ? `No entries to sync for user ${resourceNo}` : 'No entries to sync',
        duration_ms: duration,
        entries_processed: 0,
        entries_succeeded: 0,
        entries_failed: 0
      });

      return NextResponse.json({
        success: true,
        synced_entries: 0,
        failed_entries: 0,
        message: resourceNo ? `No entries to sync for user ${resourceNo}` : 'No entries to sync'
      });
    }

    logger.info('Pending entries found', { count: pendingEntries.length, companyId, resourceNo });

    // 🚀 Initialize BC Client
    const bcClient = new BusinessCentralClient(tenant, company);

    let syncedCount = 0;
    let failedCount = 0;
    const errors: string[] = [];
    const errorDetails: any[] = [];

    // 📊 Track batches and their entries
    const batchesUsed: Record<string, { count: number; hours: number }> = {};

    // 🔄 Process each entry - batch name comes from the entry itself (set during creation)
    for (const entry of pendingEntries) {
      // ❌ STRICT: batch name must be configured, no fallback
      const batchName = entry.bc_batch_name;

      if (!batchName) {
        logger.error('Entry missing batch name', { entryId: entry.id, resourceNo: entry.resource_no });

        // Mark as error
        await supabaseAdmin
          .from('time_entries')
          .update({
            bc_sync_status: 'error',
            bc_last_sync_at: new Date().toISOString()
          })
          .eq('id', entry.id);

        // Log error
        await supabaseAdmin.from('bc_sync_logs').insert({
          tenant_id: tenant.id,
          company_id: companyId,
          operation_type: 'sync_to_bc',
          time_entry_id: entry.id,
          log_level: 'error',
          message: `Entry has no batch name configured`,
          resource_no: entry.resource_no,
          details: {
            entry_id: entry.id,
            resource_no: entry.resource_no,
            error: 'bc_batch_name is null or empty'
          }
        });

        failedCount++;
        errors.push(`Entry ${entry.id}: No batch name configured`);
        errorDetails.push({
          entry_id: entry.id,
          error: 'No batch name configured',
          code: 'MISSING_BATCH_NAME'
        });
        continue; // Skip this entry
      }

      try {
        logger.debug('Syncing entry to BC', { entryId: entry.id, batch: batchName, description: entry.description });

        let bcJournalLine;

        // Check if entry was previously synced (has bc_journal_id)
        if (entry.bc_journal_id) {
          logger.debug('Updating existing BC journal line', { entryId: entry.id, journalId: entry.bc_journal_id });

          // 📝 Update existing Job Journal Line in BC
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
          logger.debug('Creating new BC journal line', { entryId: entry.id });

          // 📤 Create new Job Journal Line in BC
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

        // ✅ Update local status
        await supabaseAdmin
          .from('time_entries')
          .update({
            bc_sync_status: 'synced',
            bc_journal_id: bcJournalLine.id,
            bc_batch_name: batchName,
            bc_last_sync_at: new Date().toISOString(),
            is_editable: true // Still editable
          })
          .eq('id', entry.id);

        // Track batch usage
        if (!batchesUsed[batchName]) {
          batchesUsed[batchName] = { count: 0, hours: 0 };
        }
        batchesUsed[batchName].count++;
        batchesUsed[batchName].hours += parseFloat(entry.hours);

        syncedCount++;
        logger.info('Entry synced successfully to BC', { entryId: entry.id, batch: batchName, journalId: bcJournalLine.id });

      } catch (error) {
        logger.error('Failed to sync entry to BC', { entryId: entry.id, error });

        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const errorCode = (error as any)?.code || (error as any)?.error?.code;

        // Mark as error
        await supabaseAdmin
          .from('time_entries')
          .update({
            bc_sync_status: 'error',
            bc_last_sync_at: new Date().toISOString()
          })
          .eq('id', entry.id);

        // Log individual entry error
        await supabaseAdmin.from('bc_sync_logs').insert({
          tenant_id: tenant.id,
          company_id: companyId,
          operation_type: 'sync_to_bc',
          batch_name: batchName,
          time_entry_id: entry.id,
          log_level: 'error',
          message: `Failed to sync entry: ${entry.description}`,
          bc_error_code: errorCode,
          bc_error_message: errorMessage,
          resource_no: entry.resource_no,
          details: {
            entry_id: entry.id,
            job_bc_id: entry.job_bc_id,
            task_bc_id: entry.task_bc_id,
            hours: entry.hours,
            date: entry.date,
            error: errorMessage,
            stack: error instanceof Error ? error.stack : undefined
          }
        });

        failedCount++;
        errors.push(`Entry ${entry.id}: ${errorMessage}`);
        errorDetails.push({
          entry_id: entry.id,
          error: errorMessage,
          code: errorCode
        });
      }
    }

    // Calculate total hours
    const totalHours = pendingEntries
      .filter((e: any) => !errors.some(err => err.includes(e.id)))
      .reduce((sum: number, e: any) => sum + parseFloat(e.hours), 0);

    const duration = Date.now() - startTime;

    // 📊 Create batch records for each unique batch used
    const batchIds: string[] = [];
    if (syncedCount > 0) {
      for (const [batchName, batchInfo] of Object.entries(batchesUsed)) {
        const { data: batchData } = await supabaseAdmin
          .from('bc_sync_batches')
          .insert({
            tenant_id: tenant.id,
            company_id: companyId,
            batch_name: batchName,
            status: 'draft',
            entries_count: batchInfo.count,
            total_hours: batchInfo.hours
          })
          .select('id')
          .single();

        if (batchData?.id) {
          batchIds.push(batchData.id);
        }
        logger.info('Batch record created', { batchName, entries: batchInfo.count, hours: batchInfo.hours.toFixed(2) });
      }
    }

    // Get list of batch names used
    const batchNamesUsed = Object.keys(batchesUsed);

    // Log the overall sync operation
    await supabaseAdmin.from('bc_sync_logs').insert({
      tenant_id: tenant.id,
      company_id: companyId,
      operation_type: 'sync_to_bc',
      batch_name: batchNamesUsed.length > 0 ? batchNamesUsed.join(', ') : undefined,
      batch_id: batchIds.length > 0 ? batchIds[0] : undefined,
      log_level: failedCount > 0 ? (syncedCount > 0 ? 'warning' : 'error') : 'success',
      message: `Sync completed: ${syncedCount} succeeded, ${failedCount} failed across ${batchNamesUsed.length} batch(es)`,
      entries_processed: pendingEntries.length,
      entries_succeeded: syncedCount,
      entries_failed: failedCount,
      total_hours: totalHours,
      duration_ms: duration,
      details: {
        batches: batchesUsed,
        errors: errorDetails.length > 0 ? errorDetails : undefined
      }
    });

    logger.info('Sync to BC completed', {
      synced: syncedCount,
      failed: failedCount,
      batches: batchNamesUsed.join(', '),
      durationMs: duration
    });

    return NextResponse.json({
      success: true,
      batches_used: batchNamesUsed,
      synced_entries: syncedCount,
      failed_entries: failedCount,
      errors: errors.length > 0 ? errors : undefined,
      message: `Successfully synced ${syncedCount} entries to ${batchNamesUsed.length} batch(es)${failedCount > 0 ? `, ${failedCount} failed` : ''}`
    });

  } catch (error) {
    logger.error('Sync to BC failed with critical error', { error, tenantSlug, companyId });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const duration = Date.now() - startTime;

    // Try to log the error (best effort) - use variables from outer scope
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
            operation_type: 'sync_to_bc',
            log_level: 'error',
            message: 'Sync operation failed with critical error',
            bc_error_message: errorMessage,
            duration_ms: duration,
            entries_processed: 0,
            entries_succeeded: 0,
            entries_failed: 0,
            details: {
              error: errorMessage,
              stack: error instanceof Error ? error.stack : undefined
            }
          });
        }
      } catch (logError) {
        console.error('Failed to log error:', logError);
      }
    }

    return NextResponse.json({
      success: false,
      synced_entries: 0,
      failed_entries: 0,
      error: 'Sync failed',
      details: errorMessage
    }, { status: 500 });
  }
}