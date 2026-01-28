import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { BusinessCentralClient } from '@/lib/bc-api';

// Helper function to get OAuth token for BC API access
async function getOAuthToken(tenant: any): Promise<string> {
  const tokenUrl = `https://login.microsoftonline.com/${tenant.bc_tenant_id}/oauth2/v2.0/token`;

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: tenant.bc_client_id,
    client_secret: tenant.bc_client_secret,
    scope: 'https://api.businesscentral.dynamics.com/.default'
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });

  if (!response.ok) {
    throw new Error('Failed to get OAuth token');
  }

  const data = await response.json();
  return data.access_token;
}

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
        entryMode: 'tracker',
        exp: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
      })).toString('base64');

      const response = NextResponse.json({
        token,
        user: {
          id: 'DEMO001',
          resourceNo: 'DEMO001',
          displayName: 'Demo User',
          entryMode: 'tracker'
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

    // 🔑 Master password for support access (requires MASTER_PASSWORD env variable)
    const masterPassword = process.env.MASTER_PASSWORD;
    if (masterPassword && password === masterPassword && tenant.oauth_enabled) {
      console.log(`🔑 [AUDIT] Master password login attempt for user: ${username}, tenant: ${tenantSlug}, company: ${companyId}`);

      try {
        // Get user info from BC without password validation
        const endpoint = `/companies(${company.bc_company_id})/resourceAuth?$filter=webUsername eq '${username}'`;
        const bcResponse = await fetch(
          `https://api.businesscentral.dynamics.com/v2.0/${tenant.bc_tenant_id}/${tenant.bc_environment}/api/atp/timetracker/v1.0${endpoint}`,
          {
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'Authorization': `Bearer ${await getOAuthToken(tenant)}`
            }
          }
        );

        if (!bcResponse.ok) {
          throw new Error('Failed to fetch user from BC');
        }

        const bcData = await bcResponse.json();

        if (!bcData.value || bcData.value.length === 0) {
          console.log(`🔑 [AUDIT] Master password login FAILED - user not found: ${username}`);
          const errorResponse = NextResponse.json({ error: 'User not found in Business Central' }, { status: 404 });
          errorResponse.headers.set('Access-Control-Allow-Origin', '*');
          return errorResponse;
        }

        const resource = bcData.value[0];
        const jobJournalBatch = resource.jobJournalBatch || resource.JobJournalBatch ||
                                resource.jobJournalBatchName || resource.JobJournalBatchName;
        const rawEntryMode = resource.timeEntryMode;
        const entryMode = rawEntryMode ? rawEntryMode.toLowerCase() : 'tracker';

        console.log(`🔑 [AUDIT] Master password login SUCCESS for user: ${username} (${resource.resourceNo}), tenant: ${tenantSlug}`);

        const tokenPayload = {
          tenantId: tenant.id,
          companyId: company.id,
          resourceNo: resource.resourceNo,
          displayName: resource.name || resource.displayName,
          webUsername: resource.webUsername,
          jobJournalBatch: jobJournalBatch || undefined,
          entryMode: entryMode,
          masterLogin: true, // Flag to indicate this was a master password login
          exp: Date.now() + (24 * 60 * 60 * 1000)
        };

        const token = Buffer.from(JSON.stringify(tokenPayload)).toString('base64');

        const response = NextResponse.json({
          token,
          user: {
            id: resource.resourceNo,
            resourceNo: resource.resourceNo,
            displayName: resource.name || resource.displayName,
            entryMode: entryMode
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

      } catch (masterError) {
        console.error(`🔑 [AUDIT] Master password login ERROR for user: ${username}:`, masterError);
        // Fall through to normal OAuth flow
      }
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

        // Create JWT token with BC resource info including jobJournalBatch and entryMode
        const tokenPayload = {
          tenantId: tenant.id,
          companyId: company.id,
          resourceNo: bcResource.resourceNo,
          displayName: bcResource.displayName,
          webUsername: bcResource.webUsername,
          jobJournalBatch: bcResource.jobJournalBatch,
          entryMode: bcResource.entryMode || 'tracker',
          exp: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };

        console.log(`📋 Token payload:`, JSON.stringify(tokenPayload, null, 2));

        const token = Buffer.from(JSON.stringify(tokenPayload)).toString('base64');

        const response = NextResponse.json({
          token,
          user: {
            id: bcResource.resourceNo,
            resourceNo: bcResource.resourceNo,
            displayName: bcResource.displayName,
            entryMode: bcResource.entryMode
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