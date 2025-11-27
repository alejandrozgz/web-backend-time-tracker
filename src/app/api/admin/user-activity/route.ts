import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/user-activity?period=30
async function handler(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const period = parseInt(searchParams.get('period') || '30', 10);

    console.log(`📊 Fetching user activity analytics for last ${period} days`);

    // Get detailed user activity stats
    const { data: detailedStats, error: detailedError } = await supabaseAdmin
      .rpc('get_active_users_stats', { p_days: period });

    if (detailedError) {
      console.error('Error fetching detailed user activity:', detailedError);
      throw detailedError;
    }

    // Get summary statistics by tenant
    const { data: summaryStats, error: summaryError } = await supabaseAdmin
      .rpc('get_active_users_summary', { p_days: period });

    if (summaryError) {
      console.error('Error fetching user activity summary:', summaryError);
      throw summaryError;
    }

    console.log(`✅ Fetched activity for ${detailedStats?.length || 0} users`);
    console.log(`✅ Fetched summary for ${summaryStats?.length || 0} tenants`);

    const response = NextResponse.json({
      period,
      detailedStats: detailedStats || [],
      summaryStats: summaryStats || []
    });

    response.headers.set('Access-Control-Allow-Origin', '*');
    return response;

  } catch (error) {
    console.error('❌ Error fetching user activity:', error);
    const errorResponse = NextResponse.json(
      {
        error: 'Failed to fetch user activity',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
    errorResponse.headers.set('Access-Control-Allow-Origin', '*');
    return errorResponse;
  }
}

export const GET = withAdminAuth(handler);

export async function OPTIONS(request: NextRequest) {
  const response = new NextResponse(null, { status: 204 });
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}
