import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';
import { requirePMRole } from '@/lib/planning-auth';
import { logger } from '@/lib/logger';

function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*' };
}

function isWeekend(dateStr: string): boolean {
  const d = new Date(dateStr + 'T00:00:00');
  const day = d.getDay();
  return day === 0 || day === 6;
}

function eachDayBetween(dateFrom: string, dateTo: string): string[] {
  const days: string[] = [];
  const current = new Date(dateFrom + 'T00:00:00');
  const end = new Date(dateTo + 'T00:00:00');
  while (current <= end) {
    days.push(current.toISOString().slice(0, 10));
    current.setDate(current.getDate() + 1);
  }
  return days;
}

// GET /api/[tenant]/planning/capacity?companyId=...&dateFrom=...&dateTo=...&draftId=...&resourceNos=R1,R2
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    requirePMRole(request);
    const { tenant: tenantSlug } = await params;
    const { searchParams } = new URL(request.url);
    const companyId   = searchParams.get('companyId');
    const dateFrom    = searchParams.get('dateFrom');
    const dateTo      = searchParams.get('dateTo');
    const draftId     = searchParams.get('draftId');
    const resourceNosParam = searchParams.get('resourceNos');

    if (!companyId || !dateFrom || !dateTo) {
      return NextResponse.json({ error: 'companyId, dateFrom, dateTo required' }, { status: 400, headers: corsHeaders() });
    }

    const resourceNos: string[] = resourceNosParam ? resourceNosParam.split(',').map(r => r.trim()) : [];

    // Fetch all resources for the company
    let resourcesQuery = supabaseAdmin
      .from('resources')
      .select('resource_no, display_name, daily_capacity_hours')
      .eq('company_id', companyId)
      .eq('is_active', true);
    if (resourceNos.length > 0) resourcesQuery = resourcesQuery.in('resource_no', resourceNos);
    const { data: dbResources, error: resourcesError } = await resourcesQuery;
    if (resourcesError) throw resourcesError;

    let resources = dbResources || [];

    // If Supabase has no resources, try BC
    if (resources.length === 0) {
      const { data: tenant } = await supabaseAdmin.from('tenants').select('*').eq('slug', tenantSlug).single();
      const { data: company } = await supabaseAdmin.from('companies').select('*').eq('id', companyId).single();
      if (tenant?.oauth_enabled && company) {
        try {
          const bcResources = await new BusinessCentralClient(tenant, company).getAllResources();
          resources = bcResources.map((r: any) => ({
            resource_no: r.resourceNo,
            display_name: r.displayName,
            daily_capacity_hours: 8
          }));
        } catch (e) {
          logger.warn('BC resources fetch failed for capacity', { error: e instanceof Error ? e.message : e });
        }
      }
    }

    if (resourceNos.length > 0) {
      resources = resources.filter((r: any) => resourceNos.includes(r.resource_no));
    }

    const days = eachDayBetween(dateFrom, dateTo);
    const allResourceNos = (resources || []).map((r: any) => r.resource_no);

    // Fetch planned hours per resource per day (from draftId or all non-published drafts)
    let plannedQuery = supabaseAdmin
      .from('planning_entries')
      .select('resource_no, planning_date, planned_hours')
      .eq('company_id', companyId)
      .gte('planning_date', dateFrom)
      .lte('planning_date', dateTo);

    if (draftId) {
      plannedQuery = plannedQuery.eq('draft_id', draftId);
    } else {
      // Sum across all non-published drafts
      const { data: draftIds } = await supabaseAdmin
        .from('planning_drafts')
        .select('id')
        .eq('company_id', companyId)
        .neq('status', 'published');
      const ids = (draftIds || []).map((d: any) => d.id);
      if (ids.length > 0) plannedQuery = plannedQuery.in('draft_id', ids);
    }

    if (allResourceNos.length > 0) plannedQuery = plannedQuery.in('resource_no', allResourceNos);
    const { data: plannedEntries } = await plannedQuery;

    // Fetch actual hours from time_entries
    let actualQuery = supabaseAdmin
      .from('time_entries')
      .select('resource_no, date, hours')
      .eq('company_id', companyId)
      .gte('date', dateFrom)
      .lte('date', dateTo);
    if (allResourceNos.length > 0) actualQuery = actualQuery.in('resource_no', allResourceNos);
    const { data: actualEntries } = await actualQuery;

    // Aggregate planned hours map: resourceNo → date → sum
    const plannedMap: Record<string, Record<string, number>> = {};
    for (const e of (plannedEntries || [])) {
      if (!plannedMap[e.resource_no]) plannedMap[e.resource_no] = {};
      plannedMap[e.resource_no][e.planning_date] = (plannedMap[e.resource_no][e.planning_date] || 0) + parseFloat(e.planned_hours);
    }

    // Aggregate actual hours map
    const actualMap: Record<string, Record<string, number>> = {};
    for (const e of (actualEntries || [])) {
      if (!actualMap[e.resource_no]) actualMap[e.resource_no] = {};
      actualMap[e.resource_no][e.date] = (actualMap[e.resource_no][e.date] || 0) + parseFloat(e.hours);
    }

    // Build capacity rows
    const rows = (resources || []).map((resource: any) => {
      const dailyCap = parseFloat(resource.daily_capacity_hours) || 8.0;
      const resourcePlanned = plannedMap[resource.resource_no] || {};
      const resourceActual  = actualMap[resource.resource_no] || {};

      let totalPlanned = 0, totalActual = 0, totalCapacity = 0;

      const dayRows = days.map(date => {
        const capHours = isWeekend(date) ? 0 : dailyCap;
        const planned  = resourcePlanned[date] || 0;
        const actual   = resourceActual[date]  || 0;
        totalPlanned  += planned;
        totalActual   += actual;
        totalCapacity += capHours;
        return {
          date,
          planned_hours: planned,
          actual_hours: actual,
          capacity_hours: capHours,
          is_overloaded: capHours > 0 && planned > capHours
        };
      });

      return {
        resource_no: resource.resource_no,
        display_name: resource.display_name,
        daily_capacity_hours: dailyCap,
        days: dayRows,
        total_planned: totalPlanned,
        total_actual: totalActual,
        total_capacity: totalCapacity
      };
    });

    return NextResponse.json({ rows, dateRange: { from: dateFrom, to: dateTo } }, { headers: corsHeaders() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg === 'UNAUTHORIZED') return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders() });
    if (msg === 'FORBIDDEN')    return NextResponse.json({ error: 'PM role required' }, { status: 403, headers: corsHeaders() });
    logger.error('GET planning capacity failed', { error: msg });
    return NextResponse.json({ error: msg }, { status: 500, headers: corsHeaders() });
  }
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
