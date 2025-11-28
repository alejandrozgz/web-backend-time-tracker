import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { z } from 'zod';
import { logger } from '@/lib/logger';

/**
 * Sync Status States:
 * - 'not_synced': Not synced to BC yet (new entry)
 * - 'synced': Synced to BC as editable draft
 * - 'error': Sync failed, needs retry
 */

// 📋 Validation schema usando BC IDs
const timeEntrySchema = z.object({
  bc_job_id: z.string().min(1, 'BC Job ID required'),
  bc_task_id: z.string().min(1, 'BC Task ID required'),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Invalid date format'),
  hours: z.number().min(0.01, 'Minimum time is 36 seconds (0.01 hours)').max(24, 'Hours must be between 0.01 and 24'),
  description: z.string().min(1, 'Description required'),
  start_time: z.string().optional(),
  end_time: z.string().optional(),
  resource_no: z.string().optional()
});

// GET - Fetch time entries
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const url = new URL(request.url);
    const companyId = url.searchParams.get('companyId');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    const resourceNo = url.searchParams.get('resource_no'); // Add resource_no filter
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // Get tenant and company
    const [tenantResult, companyResult] = await Promise.all([
      supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single(),
      supabaseAdmin.from('companies').select('*').eq('id', companyId).single()
    ]);

    const { data: tenant } = tenantResult;
    const { data: company } = companyResult;

    if (!tenant || !company) {
      return NextResponse.json({ error: 'Tenant or company not found' }, { status: 404 });
    }

    // Build query
    let query = supabaseAdmin
      .from('time_entries')
      .select(`
        id,
        bc_job_id,
        bc_task_id,
        date,
        hours,
        description,
        start_time,
        end_time,
        bc_sync_status,
        bc_journal_id,
        bc_batch_name,
        bc_ledger_id,
        last_modified_at,
        bc_last_sync_at,
        is_editable,
        created_at,
        resource_no
      `)
      .eq('company_id', companyId)
      .order('date', { ascending: false })
      .order('created_at', { ascending: false });

    // Apply filters
    if (from) query = query.gte('date', from);
    if (to) query = query.lte('date', to);
    if (resourceNo) query = query.eq('resource_no', resourceNo); // Filter by resource

    const { data: entries, error } = await query.range(offset, offset + limit - 1);

    if (error) throw error;

    return NextResponse.json({
      entries: entries || []
    });

  } catch (error) {
    logger.error('Fetch time entries error', { error, tenantSlug: (await params).tenant });
	const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to fetch time entries',
      details: errorMessage
    }, { status: 500 });
  }
}

// POST - Create time entry
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const rawData = await request.json();

    logger.info('Create time entry request', { tenant: tenantSlug });
    logger.debug('Raw input data', { rawData });

    // Validate input
    const validatedData = timeEntrySchema.parse(rawData);
    logger.debug('Input validated', { validatedData });

    // Get tenant
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      throw new Error('Tenant not found');
    }

    // Get company from request or from user context
    const companyId = rawData.companyId || rawData.company_id;
    if (!companyId) {
      throw new Error('Company ID required');
    }

    const { data: company, error: companyError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('id', companyId)
      .single();

    if (companyError || !company) {
      throw new Error('Company not found');
    }

    // Extract resource and batch info from JWT token
    const authHeader = request.headers.get('authorization');
    let resourceNo = 'R0010'; // fallback
    let jobJournalBatch: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo || 'R0010';
        jobJournalBatch = decodedToken.jobJournalBatch;
        logger.debug('Token decoded', { resourceNo, jobJournalBatch: jobJournalBatch || 'NOT_CONFIGURED' });
      } catch (e) {
        logger.warn('Could not decode token, using fallback resource', { error: e });
      }
    }

    // ❌ STRICT: Fail if batch is not configured
    if (!jobJournalBatch) {
      logger.error('Batch not configured for resource', { resourceNo });
      return NextResponse.json({
        error: `Resource ${resourceNo} does not have a jobJournalBatch configured in Business Central. Please configure the batch name for this resource before creating time entries.`
      }, { status: 400 });
    }

    logger.info('Using configured batch', { batch: jobJournalBatch, resourceNo });

    // 🔍 Check for overlapping entries (same user, same day)
    const { data: existingEntries } = await supabaseAdmin
      .from('time_entries')
      .select('id, start_time, end_time, hours')
      .eq('company_id', companyId)
      .eq('resource_no', resourceNo)
      .eq('date', validatedData.date);

    // Validate no overlaps if times are provided
    if (validatedData.start_time && validatedData.end_time) {
      const hasOverlap = existingEntries?.some(entry => {
        if (!entry.start_time || !entry.end_time) return false;

        const newStart = new Date(`2000-01-01T${validatedData.start_time}`);
        const newEnd = new Date(`2000-01-01T${validatedData.end_time}`);
        const existingStart = new Date(`2000-01-01T${entry.start_time}`);
        const existingEnd = new Date(`2000-01-01T${entry.end_time}`);

        return (newStart < existingEnd && newEnd > existingStart);
      });

      if (hasOverlap) {
        return NextResponse.json({
          error: 'Time overlap detected with existing entry'
        }, { status: 400 });
      }
    }

    // 📝 Create time entry
    const newEntry = {
      tenant_id: tenant.id,
      company_id: companyId,
      bc_job_id: validatedData.bc_job_id,
      bc_task_id: validatedData.bc_task_id,
      date: validatedData.date,
      hours: validatedData.hours,
      description: validatedData.description,
      start_time: validatedData.start_time,
      end_time: validatedData.end_time,
      resource_no: resourceNo,
      bc_batch_name: jobJournalBatch, // ✅ STRICT: Must be configured, no fallback
      bc_sync_status: 'not_synced', // Initial status
      is_editable: true,
      created_at: new Date().toISOString(),
      last_modified_at: new Date().toISOString()
    };

    const { data: createdEntry, error: createError } = await supabaseAdmin
      .from('time_entries')
      .insert(newEntry)
      .select()
      .single();

    if (createError) throw createError;

    logger.info('Time entry created successfully', { entryId: createdEntry.id, resourceNo, batch: jobJournalBatch });

    return NextResponse.json({
      entry: createdEntry
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn('Time entry validation failed', { issues: error.issues });
	  return NextResponse.json({
		error: 'Validation failed',
		details: error.issues
	  }, { status: 400 });
	}

    logger.error('Create time entry error', { error });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to create time entry',
      details: errorMessage
    }, { status: 500 });
  }
}

// PATCH - Update time entry
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  const { tenant: tenantSlug } = await params;
  const url = new URL(request.url);
  const entryId = url.searchParams.get('id') || url.pathname.split('/').pop();

  try {
    const updateData = await request.json();

    if (!entryId) {
      return NextResponse.json({ error: 'Entry ID required' }, { status: 400 });
    }

    // Verificar si la entry es editable
    const { data: existingEntry, error: fetchError } = await supabaseAdmin
      .from('time_entries')
      .select('id, bc_sync_status, is_editable, company_id, bc_batch_name, bc_journal_id')
      .eq('id', entryId)
      .single();

    if (fetchError || !existingEntry) {
      return NextResponse.json({ error: 'Time entry not found' }, { status: 404 });
    }

    // No permitir edición si no es editable
    // Status: 'not_synced', 'synced', 'error'
    if (!existingEntry.is_editable) {
      return NextResponse.json({
        error: 'Cannot modify entry: not editable'
      }, { status: 400 });
    }

    // Partial validation for updates
    const allowedFields = ['hours', 'description', 'start_time', 'end_time', 'bc_job_id', 'bc_task_id'];
    const filteredData = Object.keys(updateData)
      .filter(key => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = updateData[key];
        return obj;
      }, {} as any);

    // Determine new sync status after edit
    let newSyncStatus: string;
    logger.debug('Update time entry - current status', { entryId, currentStatus: existingEntry.bc_sync_status });

    if (existingEntry.bc_sync_status === 'synced') {
      // If was synced, mark as not_synced (needs re-sync)
      newSyncStatus = 'not_synced';
    } else if (existingEntry.bc_sync_status === 'not_synced' || existingEntry.bc_sync_status === 'error') {
      // Keep valid statuses
      newSyncStatus = existingEntry.bc_sync_status;
    } else {
      // Convert any legacy/invalid status to not_synced
      logger.warn('Legacy status detected, converting to not_synced', { entryId, legacyStatus: existingEntry.bc_sync_status });
      newSyncStatus = 'not_synced';
    }

    logger.info('Updating time entry', { entryId, newStatus: newSyncStatus, updates: Object.keys(filteredData) });

    // Actualizar entry
    const { data: updatedEntry, error } = await supabaseAdmin
      .from('time_entries')
      .update({
        ...filteredData,
        last_modified_at: new Date().toISOString(),
        bc_sync_status: newSyncStatus  // Always set explicitly to a valid status
      })
      .eq('id', entryId)
      .select()
      .single();

    if (error) {
      logger.error('Supabase update error', { error, entryId });
      throw error;
    }

    logger.info('Time entry updated successfully', { entryId, finalStatus: updatedEntry?.bc_sync_status });

    if (error) throw error;

    return NextResponse.json({
      entry: updatedEntry
    });

  } catch (error) {
    logger.error('Update time entry error', { error, entryId });
	const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to update time entry',
      details: errorMessage
    }, { status: 500 });
  }
}

// DELETE - Delete time entry
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  const { tenant: tenantSlug } = await params;
  const url = new URL(request.url);
  const entryId = url.searchParams.get('id') || url.pathname.split('/').pop();

  try {

    if (!entryId) {
      return NextResponse.json({ error: 'Entry ID required' }, { status: 400 });
    }

    // 🔍 Verificar si la entry es editable
    const { data: existingEntry, error: fetchError } = await supabaseAdmin
      .from('time_entries')
      .select('id, bc_sync_status, is_editable')
      .eq('id', entryId)
      .single();

    if (fetchError || !existingEntry) {
      return NextResponse.json({ error: 'Time entry not found' }, { status: 404 });
    }

    // ❌ No permitir eliminación si no es editable
    // Status: 'not_synced', 'synced', 'error'
    if (!existingEntry.is_editable) {
      return NextResponse.json({
        error: 'Cannot delete entry: not editable'
      }, { status: 400 });
    }

    // 🗑️ Eliminar entry
    const { error } = await supabaseAdmin
      .from('time_entries')
      .delete()
      .eq('id', entryId);

    if (error) throw error;

    logger.info('Time entry deleted successfully', { entryId });

    return NextResponse.json({
      success: true,
      message: 'Time entry deleted successfully'
    });

  } catch (error) {
    logger.error('Delete time entry error', { error, entryId });
	const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to delete time entry',
      details: errorMessage
    }, { status: 500 });
  }
}