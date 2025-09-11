import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { tenant: tenantSlug } = await params;
    const url = new URL(request.url);
    const companyId = url.searchParams.get('companyId');

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // 📊 Query dashboard data
    const { data: dashboardData, error } = await supabaseAdmin
      .rpc('get_sync_dashboard', { p_company_id: companyId });

    if (error) throw error;

    const dashboard = dashboardData?.[0] || {
      local_entries: 0,
      draft_entries: 0,
      posted_entries: 0,
      error_entries: 0,
      modified_entries: 0,
      pending_hours: 0
    };

    return NextResponse.json(dashboard);

  } catch (error) {
    console.error('❌ Sync dashboard error:', error);
    return NextResponse.json({ 
      error: 'Failed to load sync dashboard',
      details: error.message 
    }, { status: 500 });
  }
}