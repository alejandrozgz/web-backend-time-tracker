async function testBCAPI() {
  const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL2FwaS5idXNpbmVzc2NlbnRyYWwuZHluYW1pY3MuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZTM1ZDZlNzItMWYyOS00NDgyLTgyYmQtNTZmNDdmMTU2MGY3LyIsImlhdCI6MTc1Njg4Mzc5NiwibmJmIjoxNzU2ODgzNzk2LCJleHAiOjE3NTY4ODc2OTYsImFpbyI6ImsyUmdZRGpBTHl1cG1PU1JzdnJwSTQ3TlM1OXdBZ0E9IiwiYXBwaWQiOiJkODAwMTM3MS1mNjZiLTRkY2QtYWY2MS1jODNmZmY0ZGNhOWYiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9lMzVkNmU3Mi0xZjI5LTQ0ODItODJiZC01NmY0N2YxNTYwZjcvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI4YzUzMzUzMi0xODM3LTQyYjEtYmJhMy0zYjEyZjNmZTBjYTQiLCJyaCI6IjEuQVhvQWNtNWQ0eWtmZ2tTQ3ZWYjBmeFZnOXozdmJabHNzMU5CaGdlbV9Ud0J1Sjk2QUFCNkFBLiIsInJvbGVzIjpbIkF1dG9tYXRpb24uUmVhZFdyaXRlLkFsbCIsImFwcF9hY2Nlc3MiLCJBZG1pbkNlbnRlci5SZWFkV3JpdGUuQWxsIiwiQVBJLlJlYWRXcml0ZS5BbGwiXSwic3ViIjoiOGM1MzM1MzItMTgzNy00MmIxLWJiYTMtM2IxMmYzZmUwY2E0IiwidGlkIjoiZTM1ZDZlNzItMWYyOS00NDgyLTgyYmQtNTZmNDdmMTU2MGY3IiwidXRpIjoiM2ZMT0tJZlRVMHk1SkRQTlo4b19BUSIsInZlciI6IjEuMCIsInhtc19mdGQiOiIzSGhjQU5VOTREWWpFUFpsM0V6bzl2ZTBYbDVWN2dkNVlRS0V0UXVjalFJQlpYVnliM0JsYm05eWRHZ3RaSE50Y3ciLCJ4bXNfaWRyZWwiOiI2IDciLCJ4bXNfcmQiOiIwLjQyTGxZQkppckJJUzRXQVhFdkJ3NzFhOE40WEhaMVhCM2VuTWg3UlRnYUtjUWdJT1FTOVduOVRaNHRUMXRfd0F4LUdJTXFBb2g1Q0E3ZnZjbVRtYmd4M2IySmY5dFdIY01SOEEifQ.ac2ve2786L-uQ1ShBMw8y6tuyeHXA0QKilmyAJlU7o33rkiCmeM_NssztCx_LuKnjdVdQ2z0MV43Oc7iJYhTFFHyYmY6breifbGdF1U4-ef1wt-sGoLIs1blZDRRyrlZxixvjdAQ-5qZ1sMY-8Z5NACnNyKtjbywwxQrcL-nyGcY50jTg-ML_r_oEh96r5nVgnyxpQzfY3xyD8Z_XoEnXzknJcpLYdHF7t5m6T_i36ML2iD3Gpv2HPyY2sx-ixQBE91qaNV44OgxPr1XTrGGPt5bxcfQaDgRBNnApWKyElH5q4VUtU2LMT3rIhG8eT9d_0kNdYaXvfJCtVe_WG1vSw';
  const tenantId = 'e35d6e72-1f29-4482-82bd-56f47f1560f7';
  const environment = 'Sandbox';
  
  let selectedCompanyId = null;
  
  // Test 1: Listar companies y obtener el ID correcto
  console.log('Testing BC API - Companies...');
  try {
    const companiesUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenantId}/${environment}/api/microsoft/automation/v2.0/companies`;
    
    const response = await fetch(companiesUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });
    
    console.log('Companies Status:', response.status);
    if (response.ok) {
      const data = await response.json();
      const companies = data.value.map(c => ({ id: c.id, name: c.displayName }));
      console.log('Available companies:', companies);
      
      // Usar la primera company disponible (o buscar "Silki")
      const silkiCompany = companies.find(c => c.name.toLowerCase().includes('silki'));
      selectedCompanyId = silkiCompany ? silkiCompany.id : companies[0]?.id;
      
      console.log('Selected Company ID:', selectedCompanyId);
    } else {
      const error = await response.text();
      console.log('Companies Error:', error);
      return; // No continuar si no podemos obtener companies
    }
  } catch (error) {
    console.error('Companies Request Error:', error.message);
    return;
  }

  if (!selectedCompanyId) {
    console.error('No company ID available');
    return;
  }

  // Test 2: Custom Time Tracker APIs
  console.log('\n=== Testing Custom Time Tracker APIs ===');
  
  // Test Jobs API
  console.log('\n1. Testing Jobs API...');
  try {
    const jobsUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenantId}/${environment}/api/timetracker/atp/v1.0/companies(${selectedCompanyId})/jobs`;
    
    const response = await fetch(jobsUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Jobs API Status:', response.status);
    console.log('Jobs API URL:', jobsUrl);
    if (response.ok) {
      const data = await response.json();
      console.log('Jobs API Response:', JSON.stringify(data, null, 2));
    } else {
      const error = await response.text();
      console.log('Jobs API Error:', error);
    }
  } catch (error) {
    console.error('Jobs API Error:', error.message);
  }

  // Test Job Tasks API
  console.log('\n2. Testing Job Tasks API...');
  try {
    const tasksUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenantId}/${environment}/api/timetracker/atp/v1.0/companies(${selectedCompanyId})/jobTasks`;
    
    const response = await fetch(tasksUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Job Tasks API Status:', response.status);
    if (response.ok) {
      const data = await response.json();
      console.log('Job Tasks API Response:', JSON.stringify(data, null, 2));
    } else {
      const error = await response.text();
      console.log('Job Tasks API Error:', error);
    }
  } catch (error) {
    console.error('Job Tasks API Error:', error.message);
  }

  // Test Resource Auth API
  console.log('\n3. Testing Resource Auth API...');
  try {
    const authUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenantId}/${environment}/api/timetracker/atp/v1.0/companies(${selectedCompanyId})/resourceAuth`;
    
    const response = await fetch(authUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Resource Auth API Status:', response.status);
    if (response.ok) {
      const data = await response.json();
      console.log('Resource Auth API Response:', JSON.stringify(data, null, 2));
    } else {
      const error = await response.text();
      console.log('Resource Auth API Error:', error);
    }
  } catch (error) {
    console.error('Resource Auth API Error:', error.message);
  }

  // Test Time Entries API
  console.log('\n4. Testing Time Entries API...');
  try {
    const timeUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenantId}/${environment}/api/timetracker/atp/v1.0/companies(${selectedCompanyId})/timeEntries`;
    
    const response = await fetch(timeUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Time Entries API Status:', response.status);
    if (response.ok) {
      const data = await response.json();
      console.log('Time Entries API Response:', JSON.stringify(data, null, 2));
    } else {
      const error = await response.text();
      console.log('Time Entries API Error:', error);
    }
  } catch (error) {
    console.error('Time Entries API Error:', error.message);
  }

  console.log('\n=== Testing Complete ===');
}

// Ejecutar el test
testBCAPI();