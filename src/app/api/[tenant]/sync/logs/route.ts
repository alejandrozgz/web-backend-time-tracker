import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const { searchParams } = new URL(request.url);

    const companyId = searchParams.get('companyId');
    const operation_type = searchParams.get('operation_type');
    const log_level = searchParams.get('log_level');
    const date_from = searchParams.get('date_from');
    const date_to = searchParams.get('date_to');
    const limit = parseInt(searchParams.get('limit') || '100');
    const offset = parseInt(searchParams.get('offset') || '0');

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // Get tenant
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Query the bc_sync_logs table directly
    let query = supabaseAdmin
      .from('bc_sync_logs')
      .select('*')
      .eq('company_id', companyId)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Apply filters
    if (operation_type) query = query.eq('operation_type', operation_type);
    if (log_level) query = query.eq('log_level', log_level);
    if (date_from) query = query.gte('created_at', new Date(date_from).toISOString());
    if (date_to) query = query.lte('created_at', new Date(date_to).toISOString());

    const { data: logs, error: logsError, count } = await query;

    if (logsError) {
      console.error('Error fetching sync logs:', logsError);
      throw logsError;
    }

    return NextResponse.json({
      logs: logs || [],
      count: count || logs?.length || 0,
      limit,
      offset
    });

  } catch (error) {
    console.error('Error in sync logs route:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to fetch sync logs', details: errorMessage },
      { status: 500 }
    );
  }
}
