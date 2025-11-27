import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/time-entries - Get all time entries with filters
async function handler(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = searchParams.get('tenant_id');
    const companyId = searchParams.get('company_id');
    const resourceNo = searchParams.get('resource_no');
    const bcSyncStatus = searchParams.get('bc_sync_status');
    const dateFrom = searchParams.get('date_from');
    const dateTo = searchParams.get('date_to');
    const limit = parseInt(searchParams.get('limit') || '100');
    const offset = parseInt(searchParams.get('offset') || '0');

    // First, get time entries with basic company info
    let query = supabaseAdmin
      .from('time_entries')
      .select('*', { count: 'exact' })
      .order('date', { ascending: false })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (companyId) query = query.eq('company_id', companyId);
    if (resourceNo) query = query.eq('resource_no', resourceNo);
    if (bcSyncStatus) query = query.eq('bc_sync_status', bcSyncStatus);
    if (dateFrom) query = query.gte('date', dateFrom);
    if (dateTo) query = query.lte('date', dateTo);

    const { data: timeEntries, error: entriesError, count } = await query;

    if (entriesError) throw entriesError;

    if (!timeEntries || timeEntries.length === 0) {
      return NextResponse.json({ entries: [], count: 0, limit, offset });
    }

    // Get unique company IDs and resource numbers
    const companyIds = [...new Set(timeEntries.map(e => e.company_id).filter(Boolean))];
    const resourceNos = [...new Set(timeEntries.map(e => e.resource_no).filter(Boolean))];

    // Fetch companies with tenants
    const { data: companies } = await supabaseAdmin
      .from('companies')
      .select('id, name, tenant_id, tenants(id, name, slug)')
      .in('id', companyIds);

    // Fetch resources
    const { data: resources } = await supabaseAdmin
      .from('resources')
      .select('resource_no, display_name')
      .in('resource_no', resourceNos);

    // Create lookup maps
    const companyMap = new Map(companies?.map(c => [c.id, c]) || []);
    const resourceMap = new Map(resources?.map(r => [r.resource_no, r]) || []);

    // Transform data with lookups
    const entries = timeEntries.map(entry => {
      const company = companyMap.get(entry.company_id);
      const resource = resourceMap.get(entry.resource_no);

      return {
        ...entry,
        company_name: company?.name,
        tenant_id: (company as any)?.tenants?.id,
        tenant_name: (company as any)?.tenants?.name,
        resource_display_name: resource?.display_name
      };
    });

    // Filter by tenant if specified
    const filteredEntries = tenantId
      ? entries.filter(e => e.tenant_id === tenantId)
      : entries;

    return NextResponse.json({ entries: filteredEntries, count: filteredEntries.length, limit, offset });

  } catch (error) {
    console.error('Error fetching time entries:', error);
    return NextResponse.json(
      { error: 'Failed to fetch time entries', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(handler);
