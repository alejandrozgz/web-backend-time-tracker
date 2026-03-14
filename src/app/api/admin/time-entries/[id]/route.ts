import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/time-entries/[id] - Get a single time entry
async function getHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const { data: entry, error } = await supabaseAdmin
      .from('time_entries')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !entry) {
      return NextResponse.json(
        { error: 'Time entry not found' },
        { status: 404 }
      );
    }

    // Get company and resource info
    const { data: company } = await supabaseAdmin
      .from('companies')
      .select('id, name, tenant_id, tenants(id, name, slug)')
      .eq('id', entry.company_id)
      .single();

    const { data: resource } = await supabaseAdmin
      .from('resources')
      .select('resource_no, display_name')
      .eq('resource_no', entry.resource_no)
      .single();

    return NextResponse.json({
      entry: {
        ...entry,
        company_name: company?.name,
        tenant_id: (company as any)?.tenants?.id,
        tenant_name: (company as any)?.tenants?.name,
        resource_display_name: resource?.display_name
      }
    });

  } catch (error) {
    console.error('Error fetching time entry:', error);
    return NextResponse.json(
      { error: 'Failed to fetch time entry', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

// PATCH /api/admin/time-entries/[id] - Update a time entry
async function patchHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();

    // Validate entry exists
    const { data: existingEntry, error: fetchError } = await supabaseAdmin
      .from('time_entries')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !existingEntry) {
      return NextResponse.json(
        { error: 'Time entry not found' },
        { status: 404 }
      );
    }

    // Fields that can be updated by admin
    const allowedFields = [
      'date',
      'hours',
      'description',
      'bc_job_id',
      'bc_task_id',
      'bc_sync_status',
      'bc_journal_id',
      'is_editable',
      'error_message'
    ];

    const updateData: Record<string, any> = {};
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        updateData[field] = body[field];
      }
    }

    // If hours or date changed and entry was synced, mark as modified
    if ((updateData.hours !== undefined || updateData.date !== undefined) &&
        existingEntry.bc_sync_status === 'synced') {
      updateData.bc_sync_status = 'not_synced';
      updateData.is_editable = true;
    }

    updateData.updated_at = new Date().toISOString();

    const { data: updatedEntry, error: updateError } = await supabaseAdmin
      .from('time_entries')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) {
      console.error('Error updating time entry:', updateError);
      return NextResponse.json(
        { error: 'Failed to update time entry', details: updateError.message },
        { status: 500 }
      );
    }

    console.log(`📝 Admin updated time entry ${id}:`, updateData);

    return NextResponse.json({
      success: true,
      entry: updatedEntry,
      message: 'Time entry updated successfully'
    });

  } catch (error) {
    console.error('Error updating time entry:', error);
    return NextResponse.json(
      { error: 'Failed to update time entry', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

// DELETE /api/admin/time-entries/[id] - Delete a time entry
async function deleteHandler(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // Validate entry exists
    const { data: existingEntry, error: fetchError } = await supabaseAdmin
      .from('time_entries')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !existingEntry) {
      return NextResponse.json(
        { error: 'Time entry not found' },
        { status: 404 }
      );
    }

    // Warn if entry is synced
    if (existingEntry.bc_sync_status === 'synced' && existingEntry.bc_journal_id) {
      console.warn(`⚠️ Admin deleting synced time entry ${id} with BC journal ID: ${existingEntry.bc_journal_id}`);
    }

    const { error: deleteError } = await supabaseAdmin
      .from('time_entries')
      .delete()
      .eq('id', id);

    if (deleteError) {
      console.error('Error deleting time entry:', deleteError);
      return NextResponse.json(
        { error: 'Failed to delete time entry', details: deleteError.message },
        { status: 500 }
      );
    }

    console.log(`🗑️ Admin deleted time entry ${id}`);

    return NextResponse.json({
      success: true,
      message: 'Time entry deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting time entry:', error);
    return NextResponse.json(
      { error: 'Failed to delete time entry', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(getHandler);
export const PATCH = withAdminAuth(patchHandler);
export const DELETE = withAdminAuth(deleteHandler);
