import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { withAdminAuth } from '@/middleware/adminAuth';

// GET /api/admin/companies
async function getHandler(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = searchParams.get('tenant_id');
    const isActive = searchParams.get('is_active');
    const search = searchParams.get('search');
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    let query = supabaseAdmin
      .from('companies')
      .select(`
        *,
        tenants!inner(id, name, slug)
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (tenantId) query = query.eq('tenant_id', tenantId);
    if (isActive !== null) query = query.eq('is_active', isActive === 'true');
    if (search) query = query.ilike('name', `%${search}%`);

    const { data, error, count } = await query;

    if (error) throw error;

    // Transform data
    const companies = data?.map(company => ({
      ...company,
      tenant_name: (company.tenants as any)?.name,
      tenant_slug: (company.tenants as any)?.slug
    })) || [];

    return NextResponse.json({ companies, count: count || 0, limit, offset });

  } catch (error) {
    console.error('Error fetching companies:', error);
    return NextResponse.json(
      { error: 'Failed to fetch companies', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

// POST /api/admin/companies
async function postHandler(request: NextRequest) {
  try {
    const data = await request.json();

    if (!data.tenant_id || !data.bc_company_id || !data.name) {
      return NextResponse.json(
        { error: 'Missing required fields: tenant_id, bc_company_id, name' },
        { status: 400 }
      );
    }

    const { data: company, error } = await supabaseAdmin
      .from('companies')
      .insert({
        tenant_id: data.tenant_id,
        bc_company_id: data.bc_company_id,
        name: data.name,
        bc_web_service_url: data.bc_web_service_url
      })
      .select()
      .single();

    if (error) throw error;

    return NextResponse.json({ company }, { status: 201 });

  } catch (error) {
    console.error('Error creating company:', error);
    return NextResponse.json(
      { error: 'Failed to create company', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}

export const GET = withAdminAuth(getHandler);
export const POST = withAdminAuth(postHandler);
