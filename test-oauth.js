// Usar fetch nativo de Node.js 18+
async function testOAuth() {
  const tenantId = 'e35d6e72-1f29-4482-82bd-56f47f1560f7';
  const clientId = 'd8001371-f66b-4dcd-af61-c83fff4dca9f';
  const clientSecret = '3kb8Q~xidycNYSgLI5gyfETsNOi0hDbep_N0TcEO';
  
  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
  
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'https://api.businesscentral.dynamics.com/.default'
  });

  try {
    console.log('Testing OAuth with:');
    console.log('Tenant ID:', tenantId);
    console.log('Client ID:', clientId);
    console.log('URL:', tokenUrl);
    
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    });

    const data = await response.json();
    console.log('\nOAuth Response:', JSON.stringify(data, null, 2));
    
    if (data.access_token) {
      console.log('\n✅ OAuth SUCCESS - Token obtenido');
      console.log('Token length:', data.access_token.length);
      return data.access_token;
    } else {
      console.log('\n❌ OAuth FAILED');
      console.log('Error:', data.error);
      console.log('Description:', data.error_description);
    }
  } catch (error) {
    console.error('\n❌ Network Error:', error.message);
  }
}

testOAuth();