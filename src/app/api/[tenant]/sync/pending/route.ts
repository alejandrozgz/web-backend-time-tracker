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

    console.log('🔍 ===== GET PENDING SYNC ENTRIES =====');
    console.log('🔍 Tenant:', tenantSlug);
    console.log('🔍 Company ID:', companyId);

    if (!companyId) {
      return NextResponse.json({ error: 'Company ID required' }, { status: 400 });
    }

    // 🔑 Extract resourceNo from JWT token to filter by user
    const authHeader = request.headers.get('authorization');
    let resourceNo: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
        resourceNo = decodedToken.resourceNo;
        console.log('🔍 Resource No:', resourceNo);
      } catch (e) {
        console.warn('Could not decode token for user filtering', { error: e });
      }
    }

    // 📊 Get pending entries using the SQL function (filtered by user)
    const { data: entries, error } = await supabaseAdmin
      .rpc('get_pending_sync_entries', {
        p_company_id: companyId,
        p_resource_no: resourceNo  // 🔑 Filter by current user
      });

    if (error) {
      console.error('❌ Error getting pending entries:', error);
      throw error;
    }

    console.log(`📊 Found ${entries?.length || 0} pending entries for user ${resourceNo || 'ALL'}`);

    return NextResponse.json({
      entries: entries || [],
      count: entries?.length || 0
    });

  } catch (error) {
	  console.error('❌ Get pending entries error:', error);
	  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
	  return NextResponse.json({ 
		error: 'Failed to get pending entries',
		details: errorMessage,  // ✅ CORRECTO
		entries: [],
		count: 0
	  }, { status: 500 });
	}
}