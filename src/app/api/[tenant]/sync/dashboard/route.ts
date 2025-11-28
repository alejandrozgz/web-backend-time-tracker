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

    // 🔑 Extract resourceNo from JWT token to filter dashboard by user
    const authHeader = request.headers.get('authorization');
    let resourceNo: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo;
      } catch (e) {
        console.warn('Could not decode token for user filtering in dashboard', { error: e });
      }
    }

    // 📊 Query dashboard data (filtered by user's resourceNo)
    const { data: dashboardData, error } = await supabaseAdmin
      .rpc('get_sync_dashboard', {
        p_company_id: companyId,
        p_resource_no: resourceNo  // 🔑 Filter by current user
      });

    if (error) throw error;

    const dashboard = dashboardData?.[0] || {
      not_synced_entries: 0,
      synced_entries: 0,
      error_entries: 0,
      pending_hours: 0
    };

    return NextResponse.json(dashboard);

  } catch (error) {
	  console.error('❌ Dashboard error:', error);
	  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
	  return NextResponse.json({
		error: 'Failed to load sync dashboard',
		details: errorMessage  // ✅ CORRECTO
	  }, { status: 500 });
	}
}