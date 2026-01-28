import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { z } from 'zod';
import { logger } from '@/lib/logger';

const bulkEntrySchema = z.object({
  bc_job_id: z.string().min(1),
  bc_task_id: z.string().min(1),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  hours: z.number().min(0).max(24),  // Allow 0 to delete entries
  description: z.string().min(1)
});

const bulkSaveSchema = z.object({
  companyId: z.string().uuid(),
  entries: z.array(bulkEntrySchema).min(1).max(100)
});

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const rawData = await request.json();

    logger.info('Bulk save time entries', { tenant: tenantSlug, rawData });

    const validatedData = bulkSaveSchema.parse(rawData);

    // Get tenant
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      throw new Error('Tenant not found');
    }

    // Get company
    const { data: company, error: companyError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('id', validatedData.companyId)
      .single();

    if (companyError || !company) {
      throw new Error('Company not found');
    }

    // Extract resource from JWT
    const authHeader = request.headers.get('authorization');
    let resourceNo = 'R0010';
    let jobJournalBatch: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo || 'R0010';
        jobJournalBatch = decodedToken.jobJournalBatch;
      } catch (e) {
        logger.warn('Could not decode token', { error: e });
      }
    }

    // Require batch configuration
    if (!jobJournalBatch) {
      return NextResponse.json({
        error: `Resource ${resourceNo} does not have a jobJournalBatch configured`
      }, { status: 400 });
    }

    const results = {
      created: 0,
      updated: 0,
      deleted: 0,
      failed: 0,
      errors: [] as Array<{ entry: any; error: string }>
    };

    // Process each entry
    for (const entry of validatedData.entries) {
      try {
        // Check if entries exist (may be multiple duplicates!)
        const { data: existingEntries } = await supabaseAdmin
          .from('time_entries')
          .select('id, hours, is_editable, bc_sync_status')
          .eq('company_id', validatedData.companyId)
          .eq('resource_no', resourceNo)
          .eq('bc_job_id', entry.bc_job_id)
          .eq('bc_task_id', entry.bc_task_id)
          .eq('date', entry.date)
          .order('created_at', { ascending: true });

        // 🔄 DEDUPLICATION: If multiple entries exist, unify them
        if (existingEntries && existingEntries.length > 1) {
          logger.warn('Duplicate entries found, unifying...', {
            count: existingEntries.length,
            bc_job_id: entry.bc_job_id,
            bc_task_id: entry.bc_task_id,
            date: entry.date,
            resourceNo
          });

          // Separate editable from non-editable entries
          const editableEntries = existingEntries.filter(e => e.is_editable);
          const nonEditableEntries = existingEntries.filter(e => !e.is_editable);

          // Calculate hours
          const nonEditableHours = nonEditableEntries.reduce((sum, e) => sum + e.hours, 0);
          const editableHours = editableEntries.reduce((sum, e) => sum + e.hours, 0);
          const totalCurrentHours = nonEditableHours + editableHours;

          logger.info('Deduplication analysis', {
            total: existingEntries.length,
            editable: editableEntries.length,
            nonEditable: nonEditableEntries.length,
            nonEditableHours,
            editableHours,
            totalCurrentHours,
            requestedHours: entry.hours
          });

          // Strategy:
          // 1. Keep all non-editable entries (can't touch them)
          // 2. Calculate: newEditableHours = requestedHours - nonEditableHours
          // 3. If newEditableHours > 0: keep ONE editable with that amount
          // 4. If newEditableHours <= 0: delete all editables

          const newEditableHours = Math.max(0, entry.hours - nonEditableHours);

          logger.info('Calculated editable hours needed', {
            requestedHours: entry.hours,
            nonEditableHours,
            newEditableHours
          });

          if (editableEntries.length > 0) {
            // Keep the first editable, delete the rest
            const [keepEditable, ...extraEditables] = editableEntries;

            // Delete extra editable entries
            for (const duplicate of extraEditables) {
              const { error: deleteError } = await supabaseAdmin
                .from('time_entries')
                .delete()
                .eq('id', duplicate.id);

              if (deleteError) {
                logger.error('Failed to delete duplicate', { id: duplicate.id, error: deleteError });
              } else {
                logger.info('Deleted duplicate editable entry', { id: duplicate.id });
                results.deleted++;
              }
            }

            // Now handle the kept editable entry
            if (newEditableHours > 0) {
              // Update with the calculated hours
              const { error: updateError } = await supabaseAdmin
                .from('time_entries')
                .update({
                  hours: newEditableHours,
                  description: entry.description,
                  last_modified_at: new Date().toISOString(),
                  bc_sync_status: 'not_synced'
                })
                .eq('id', keepEditable.id);

              if (updateError) throw updateError;
              logger.info('Updated editable entry with calculated hours', {
                id: keepEditable.id,
                hours: newEditableHours
              });
              results.updated++;
            } else {
              // No editable hours needed - delete the kept editable too
              const { error: deleteError } = await supabaseAdmin
                .from('time_entries')
                .delete()
                .eq('id', keepEditable.id);

              if (deleteError) throw deleteError;
              logger.info('Deleted editable entry (no additional hours needed)', { id: keepEditable.id });
              results.deleted++;
            }
          } else if (newEditableHours > 0) {
            // No editable entries exist, but we need to add hours beyond the non-editable ones
            // Create a new editable entry
            const { error: createError } = await supabaseAdmin
              .from('time_entries')
              .insert({
                tenant_id: tenant.id,
                company_id: validatedData.companyId,
                bc_job_id: entry.bc_job_id,
                bc_task_id: entry.bc_task_id,
                date: entry.date,
                hours: newEditableHours,
                description: entry.description,
                resource_no: resourceNo,
                bc_batch_name: jobJournalBatch,
                bc_sync_status: 'not_synced',
                is_editable: true,
                created_at: new Date().toISOString(),
                last_modified_at: new Date().toISOString()
              });

            if (createError) throw createError;
            logger.info('Created new editable entry for additional hours', { hours: newEditableHours });
            results.created++;
          }
          // If newEditableHours <= 0 and no editables exist, nothing to do
        } else if (existingEntries && existingEntries.length === 1) {
          // Single existing entry - normal flow
          const existing = existingEntries[0];

          // Check if editable
          if (!existing.is_editable) {
            throw new Error('Entry is not editable');
          }

          // If hours = 0, delete the entry
          if (entry.hours === 0) {
            const { error: deleteError } = await supabaseAdmin
              .from('time_entries')
              .delete()
              .eq('id', existing.id);

            if (deleteError) throw deleteError;
            results.deleted++;
          } else {
            // Update existing entry
            const { error: updateError } = await supabaseAdmin
              .from('time_entries')
              .update({
                hours: entry.hours,
                description: entry.description,
                last_modified_at: new Date().toISOString(),
                bc_sync_status: 'not_synced'
              })
              .eq('id', existing.id);

            if (updateError) throw updateError;
            results.updated++;
          }
        } else if (entry.hours > 0) {
          // No existing entries - create new one
          const { error: createError } = await supabaseAdmin
            .from('time_entries')
            .insert({
              tenant_id: tenant.id,
              company_id: validatedData.companyId,
              bc_job_id: entry.bc_job_id,
              bc_task_id: entry.bc_task_id,
              date: entry.date,
              hours: entry.hours,
              description: entry.description,
              resource_no: resourceNo,
              bc_batch_name: jobJournalBatch,
              bc_sync_status: 'not_synced',
              is_editable: true,
              created_at: new Date().toISOString(),
              last_modified_at: new Date().toISOString()
            });

          if (createError) throw createError;
          results.created++;
        }
      } catch (entryError) {
        results.failed++;
        const errorMessage = entryError instanceof Error ? entryError.message : 'Unknown error';
        results.errors.push({ entry, error: errorMessage });
        logger.error('Failed to process entry', { entry, error: entryError });
      }
    }

    logger.info('Bulk save completed', results);

    return NextResponse.json({
      success: results.failed === 0,
      ...results
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.error('Bulk save validation failed', { issues: error.issues });
      return NextResponse.json({
        error: 'Validation failed',
        details: error.issues
      }, { status: 400 });
    }

    logger.error('Bulk save error', { error });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to save time entries',
      details: errorMessage
    }, { status: 500 });
  }
}
