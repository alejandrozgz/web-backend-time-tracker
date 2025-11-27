import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ tenant: string }> }
) {
  try {
    const { username, password, companyId } = await request.json();
    const { tenant: tenantSlug } = await params;

    console.log('🔍 Login attempt:', { tenantSlug, username, companyId });

    // Get tenant from Supabase
    const { data: tenant, error: tenantError } = await supabaseAdmin
      .from('tenants')
      .select('*')
      .eq('slug', tenantSlug)
      .single();

    if (tenantError || !tenant) {
      const errorResponse = NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
      errorResponse.headers.set('Access-Control-Allow-Origin', '*');
      return errorResponse;
    }

    // Get company from Supabase
    const { data: company, error: companyError } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('id', companyId)
      .eq('tenant_id', tenant.id)
      .single();

    if (companyError || !company) {
      const errorResponse = NextResponse.json({ error: 'Company not found' }, { status: 404 });
      errorResponse.headers.set('Access-Control-Allow-Origin', '*');
      return errorResponse;
    }

    // ✅ SIEMPRE permitir demo mode para debugging
    if (username === 'demo' && password === '123') {
      console.log('✅ Demo login successful');
      
      const token = Buffer.from(JSON.stringify({
        tenantId: tenant.id,
        companyId: company.id,
        resourceNo: 'DEMO001',
        displayName: 'Demo User',
        webUsername: 'demo',
        exp: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
      })).toString('base64');

      const response = NextResponse.json({
        token,
        user: {
          id: 'DEMO001',
          resourceNo: 'DEMO001',
          displayName: 'Demo User'
        },
        tenant: {
          id: tenant.id,
          slug: tenant.slug,
          name: tenant.name
        },
        company: {
          id: company.id,
          name: company.name
        }
      });

      response.headers.set('Access-Control-Allow-Origin', '*');
      return response;
    }

    // Production mode with OAuth 2.0 (if enabled for this tenant)
    if (tenant.oauth_enabled && tenant.bc_client_id && tenant.bc_client_secret && tenant.bc_tenant_id) {
      try {
        console.log(`🔍 Attempting BC OAuth login for tenant ${tenant.slug}, user ${username}`);
        
        const bcClient = new BusinessCentralClient(tenant, company);

        // Validate resource exists and is active
        const bcResource = await bcClient.validateResourceCredentials(username, password);

        if (!bcResource || !bcResource.isActive) {
          const errorResponse = NextResponse.json({ 
            error: 'Invalid credentials or user inactive in Business Central' 
          }, { status: 401 });
          errorResponse.headers.set('Access-Control-Allow-Origin', '*');
          return errorResponse;
        }

        console.log(`✅ BC OAuth success for user ${bcResource.resourceNo}`);
        console.log(`📋 bcResource object:`, JSON.stringify(bcResource, null, 2));
        console.log(`📋 jobJournalBatch value:`, bcResource.jobJournalBatch);
        console.log(`📋 jobJournalBatch type:`, typeof bcResource.jobJournalBatch);

        // Note: User activity is tracked via time_entries.resource_no and time_entries.last_modified_at
        // No separate users table needed

        // Create JWT token with BC resource info including jobJournalBatch
        const tokenPayload = {
          tenantId: tenant.id,
          companyId: company.id,
          resourceNo: bcResource.resourceNo,
          displayName: bcResource.displayName,
          webUsername: bcResource.webUsername,
          jobJournalBatch: bcResource.jobJournalBatch,
          exp: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };

        console.log(`📋 Token payload:`, JSON.stringify(tokenPayload, null, 2));

        const token = Buffer.from(JSON.stringify(tokenPayload)).toString('base64');

        const response = NextResponse.json({
          token,
          user: {
            id: bcResource.resourceNo,
            resourceNo: bcResource.resourceNo,
            displayName: bcResource.displayName
          },
          tenant: {
            id: tenant.id,
            slug: tenant.slug,
            name: tenant.name
          },
          company: {
            id: company.id,
            name: company.name
          }
        });

        response.headers.set('Access-Control-Allow-Origin', '*');
        return response;

      } catch (bcError) {
		  console.error(`❌ Business Central OAuth error for tenant ${tenant.slug}:`, bcError);
		  
		  // ✅ FIX: Manejar bcError como unknown
		  const errorMessage = bcError instanceof Error ? bcError.message : 'Unknown error';
		  
		  // ❌ NO FALLBACK - Devolver error real
		  const errorResponse = NextResponse.json({ 
			error: `Business Central authentication failed: ${errorMessage}. Try demo/123 for testing.` 
		  }, { status: 401 });
        errorResponse.headers.set('Access-Control-Allow-Origin', '*');
        return errorResponse;
      }
    }

    // Si no hay OAuth habilitado, sugerir demo mode
    const errorResponse = NextResponse.json({ 
      error: `OAuth not configured for tenant ${tenant.slug}. Use demo/123 for testing or contact administrator.` 
    }, { status: 503 });
    errorResponse.headers.set('Access-Control-Allow-Origin', '*');
    return errorResponse;

  } catch (error) {
    console.error('❌ Login error:', error);
    const errorResponse = NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    );
    errorResponse.headers.set('Access-Control-Allow-Origin', '*');
    return errorResponse;
  }
}

export async function OPTIONS(request: NextRequest) {
  console.log('🔍 CORS preflight request');
  const response = new NextResponse(null, { status: 204 });
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}