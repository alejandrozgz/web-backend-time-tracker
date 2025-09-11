import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { z } from 'zod';

// 📋 Validation schema usando BC IDs
const timeEntrySchema = z.object({
  bc_job_id: z.string().min(1, 'BC Job ID required'),
  bc_task_id: z.string().min(1, 'BC Task ID required'),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Invalid date format'),
  hours: z.number().min(0.1).max(24, 'Hours must be between 0.1 and 24'),
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

    // Apply date filters
    if (from) query = query.gte('date', from);
    if (to) query = query.lte('date', to);

    const { data: entries, error } = await query.limit(100);

    if (error) throw error;

    return NextResponse.json({
      entries: entries || []
    });

  } catch (error) {
    console.error('❌ Fetch time entries error:', error);
    return NextResponse.json({ 
      error: 'Failed to fetch time entries',
      details: error.message 
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

    console.log('🔵 ===== CREATE TIME ENTRY =====');
    console.log('🔍 Raw input:', rawData);

    // Validate input
    const validatedData = timeEntrySchema.parse(rawData);
    console.log('✅ Validated data:', validatedData);

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

    // Extract resource from JWT token
    const authHeader = request.headers.get('authorization');
    let resourceNo = 'R0010'; // fallback

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo || 'R0010';
        console.log('Using resource from token:', resourceNo);
      } catch (e) {
        console.log('Could not decode token, using fallback resource');
      }
    }

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
      bc_sync_status: 'local', // Initial status
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

    console.log('✅ Entry created:', createdEntry.id);

    return NextResponse.json({
      entry: createdEntry
    });

  } catch (error) {
    console.error('❌ Create time entry error:', error);
    
    if (error instanceof z.ZodError) {
      return NextResponse.json({ 
        error: 'Validation failed',
        details: error.errors 
      }, { status: 400 });
    }

    return NextResponse.json({ 
      error: 'Failed to create time entry',
      details: error.message 
    }, { status: 500 });
  }
}

// PATCH - Update time entry
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const url = new URL(request.url);
    const entryId = url.searchParams.get('id') || url.pathname.split('/').pop();
    const updateData = await request.json();

    if (!entryId) {
      return NextResponse.json({ error: 'Entry ID required' }, { status: 400 });
    }

    // 🔍 Verificar si la entry es editable
    const { data: existingEntry, error: fetchError } = await supabaseAdmin
      .from('time_entries')
      .select('id, bc_sync_status, is_editable, company_id')
      .eq('id', entryId)
      .single();

    if (fetchError || !existingEntry) {
      return NextResponse.json({ error: 'Time entry not found' }, { status: 404 });
    }

    // ❌ No permitir edición si está posted
    if (!existingEntry.is_editable || existingEntry.bc_sync_status === 'posted') {
      return NextResponse.json({ 
        error: 'Cannot modify entry: already posted in Business Central' 
      }, { status: 400 });
    }

    // 🔄 Partial validation for updates
    const allowedFields = ['hours', 'description', 'start_time', 'end_time', 'bc_job_id', 'bc_task_id'];
    const filteredData = Object.keys(updateData)
      .filter(key => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = updateData[key];
        return obj;
      }, {} as any);

    // 📝 Actualizar entry
    const { data: updatedEntry, error } = await supabaseAdmin
      .from('time_entries')
      .update({
        ...filteredData,
        last_modified_at: new Date().toISOString(),
        // Si ya estaba sincronizada, marcar como modificada
        ...(existingEntry.bc_sync_status === 'draft' && { bc_sync_status: 'modified' })
      })
      .eq('id', entryId)
      .select()
      .single();

    if (error) throw error;

    return NextResponse.json({
      entry: updatedEntry
    });

  } catch (error) {
    console.error('❌ Update time entry error:', error);
    return NextResponse.json({ 
      error: 'Failed to update time entry',
      details: error.message 
    }, { status: 500 });
  }
}

// DELETE - Delete time entry
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const url = new URL(request.url);
    const entryId = url.searchParams.get('id') || url.pathname.split('/').pop();

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

    // ❌ No permitir eliminación si está posted
    if (!existingEntry.is_editable || existingEntry.bc_sync_status === 'posted') {
      return NextResponse.json({ 
        error: 'Cannot delete entry: already posted in Business Central' 
      }, { status: 400 });
    }

    // 🗑️ Eliminar entry
    const { error } = await supabaseAdmin
      .from('time_entries')
      .delete()
      .eq('id', entryId);

    if (error) throw error;

    return NextResponse.json({
      success: true,
      message: 'Time entry deleted successfully'
    });

  } catch (error) {
    console.error('❌ Delete time entry error:', error);
    return NextResponse.json({ 
      error: 'Failed to delete time entry',
      details: error.message 
    }, { status: 500 });
  }
}