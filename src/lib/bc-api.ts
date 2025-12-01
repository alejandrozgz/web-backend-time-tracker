interface BCTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export class BusinessCentralClient {
  private baseUrl: string;
  private companyId: string;
  private clientId?: string;
  private clientSecret?: string;
  private azureTenantId?: string;
  private accessToken?: string;
  private tokenExpiry?: number;

  constructor(tenant: any, company: any) {
    this.baseUrl = `https://api.businesscentral.dynamics.com/v2.0/${tenant.bc_tenant_id}/${tenant.bc_environment}/api/atp/timetracker/v1.0`;
    this.companyId = company.bc_company_id;
    
    // OAuth config from tenant
    this.clientId = tenant.bc_client_id;
    this.clientSecret = tenant.bc_client_secret;
    this.azureTenantId = tenant.bc_tenant_id;
}

  private async getAccessToken(): Promise<string> {
    if (!this.clientId || !this.clientSecret || !this.azureTenantId) {
      throw new Error('OAuth not configured for this tenant');
    }

    // Check if current token is still valid
    if (this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      console.log('🔑 Using cached OAuth token');
      return this.accessToken;
    }

    // Get new token using client credentials flow
    const tokenUrl = `https://login.microsoftonline.com/${this.azureTenantId}/oauth2/v2.0/token`;
    
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: `https://api.businesscentral.dynamics.com/.default`
    });

    console.log('🔑 Requesting new OAuth token...');
    console.log('🔗 OAuth URL:', tokenUrl);
    console.log('📋 OAuth params:', {
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: '***HIDDEN***',
      scope: 'https://api.businesscentral.dynamics.com/.default'
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params
    });

    console.log('🔑 OAuth response status:', response.status);

    if (!response.ok) {
      const error = await response.text();
      console.error('❌ OAuth failed:', error);
      throw new Error(`Failed to get OAuth token: ${error}`);
    }

    const tokenData: BCTokenResponse = await response.json();
    console.log('✅ OAuth token obtained, expires in:', tokenData.expires_in, 'seconds');
    
    this.accessToken = tokenData.access_token;
    this.tokenExpiry = Date.now() + (tokenData.expires_in * 1000) - 60000; // 1 minute buffer
    
    return this.accessToken;
  }

  private async getHeaders(): Promise<Record<string, string>> {
    const token = await this.getAccessToken();
    
    return {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`
    };
  }

  // ✅ Universal logging method for all BC API calls
  private async callBCApi(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = await this.getHeaders();
    
    const fullOptions = {
      ...options,
      headers: { ...headers, ...options.headers }
    };

    console.log('\n🚀 ===== BC API CALL =====');
    console.log('📍 URL:', url);
    console.log('🔧 Method:', options.method || 'GET');
    console.log('📋 Headers:', JSON.stringify(fullOptions.headers, null, 2));
    if (options.body) {
      console.log('📦 Body:', options.body);
    }
    
    const startTime = Date.now();
    
    try {
      const response = await fetch(url, fullOptions);
      const duration = Date.now() - startTime;
      
      console.log('✅ Response Status:', response.status, response.statusText);
      console.log('⏱️  Response Time:', duration + 'ms');
      console.log('📊 Response Headers:', JSON.stringify(Object.fromEntries(response.headers.entries()), null, 2));

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ BC API Error Response:', errorText);
        throw new Error(`BC API Error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('📄 Response Data:', JSON.stringify(data, null, 2));
      console.log('🔚 ===== END BC API CALL =====\n');
      
      return data;
      
    } catch (error) {
	  const duration = Date.now() - startTime;
	  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
	  console.error('❌ BC API Call Failed:', errorMessage);  // ✅ CORRECTO
	  console.error('⏱️ Failed after:', duration + 'ms');
	  console.error('🔚 ===== END BC API CALL (ERROR) =====\n');
	  throw error;
	}
  }

  async validateResourceCredentials(username: string, password: string) {
    try {
      const endpoint = `/companies(${this.companyId})/resourceAuth?$filter=webUsername eq '${username}'`;
      const data = await this.callBCApi(endpoint);

      if (!data.value || data.value.length === 0) {
        throw new Error('Invalid credentials - user not found');
      }

      const resource = data.value[0];

      console.log(`📋 Raw resource object:`, JSON.stringify(resource, null, 2));
      console.log(`📋 Resource fields:`, Object.keys(resource));

      // Try different possible field names for job journal batch
      const jobJournalBatch = resource.jobJournalBatch || resource.JobJournalBatch ||
                              resource.jobJournalBatchName || resource.JobJournalBatchName;

      console.log(`📋 Checked field variations:`);
      console.log(`  - resource.jobJournalBatch: ${resource.jobJournalBatch}`);
      console.log(`  - resource.JobJournalBatch: ${resource.JobJournalBatch}`);
      console.log(`  - resource.jobJournalBatchName: ${resource.jobJournalBatchName}`);
      console.log(`  - resource.JobJournalBatchName: ${resource.JobJournalBatchName}`);
      console.log(`📋 Final jobJournalBatch value: ${jobJournalBatch || 'NOT FOUND'}`);

      return {
        resourceNo: resource.resourceNo,
        displayName: resource.name || resource.displayName,
        webUsername: resource.webUsername,
        isActive: resource.blocked !== true,
        jobJournalBatch: jobJournalBatch || undefined
      };
    } catch (error) {
      console.error('BC Auth error:', error);
      throw error;
    }
  }

  async getResourceAssignments(resourceNo: string): Promise<{ jobs: any[], tasks: any[] }> {
    try {
      // First get job planning lines for this resource
      const endpoint = `/companies(${this.companyId})/jobPlanningLines?$filter=no eq '${resourceNo}' and type eq 'Resource'&$select=jobNo,jobTaskNo,description,quantity`;
      const data = await this.callBCApi(endpoint);
      
      if (!data.value || data.value.length === 0) {
        console.log('No job planning lines found for resource:', resourceNo);
        return { jobs: [], tasks: [] };
      }

      console.log(`Found ${data.value.length} job planning lines for resource ${resourceNo}`);

      // Extract unique job numbers AND job task numbers where the resource is assigned
		const uniqueJobNos = [...new Set(data.value.map((line: any) => line.jobNo))];
		const assignedTaskKeys = new Set(data.value.map((line: any) => `${line.jobNo}-${line.jobTaskNo}`));
      
      console.log('Unique job numbers:', uniqueJobNos);
      console.log('Assigned task keys:', Array.from(assignedTaskKeys));

      if (uniqueJobNos.length === 0) {
        return { jobs: [], tasks: [] };
      }

      // Get job details for the assigned jobs only
      const jobFilter = uniqueJobNos.map(jobNo => `no eq '${jobNo}'`).join(' or ');
      const jobsEndpoint = `/companies(${this.companyId})/jobs?$filter=${jobFilter}`;
      const jobsData = await this.callBCApi(jobsEndpoint);

      // Get job tasks for the assigned jobs only
      const tasksFilter = uniqueJobNos.map(jobNo => `jobNo eq '${jobNo}'`).join(' or ');
	  const tasksEndpoint = `/companies(${this.companyId})/jobTasks?$filter=(${tasksFilter}) and jobTaskType eq 'Posting'`;
      const tasksData = await this.callBCApi(tasksEndpoint);

      const jobs = jobsData.value || [];
      
      // Filter tasks to only show tasks where the resource is actually assigned
      const allTasks = tasksData.value || [];
      const assignedTasks = allTasks.filter((task: any) => {
		  const taskKey = `${task.jobNo}-${task.jobTaskNo}`;
		  return assignedTaskKeys.has(taskKey);
		});

      console.log(`Retrieved ${jobs.length} assigned jobs and ${assignedTasks.length}/${allTasks.length} assigned tasks`);

      return { jobs, tasks: assignedTasks };

    } catch (error) {
      console.error('BC Resource Assignments error:', error);
      return { jobs: [], tasks: [] };
    }
  }

  async createJobJournalLine(journalLine: any): Promise<any> {
    try {
      // 📝 Crear Job Journal Line (editable)
      const endpoint = `/companies(${this.companyId})/jobJournalLines`;
      const data = await this.callBCApi(endpoint, {
        method: 'POST',
        body: JSON.stringify(journalLine)
      });
      return data;
    } catch (error) {
      console.error('BC Create Job Journal Line error:', error);
      throw error;
    }
  }

  async updateJobJournalLine(journalLine: any): Promise<any> {
    try {
      // 📝 Update existing Job Journal Line (editable)
      // BC requires composite keys for PATCH operations
      const { id, journalTemplateName, journalBatchName, lineNo, ...updateData } = journalLine;

      let endpoint;
      let finalLineNo = lineNo;
      let etag: string | undefined;

      // If we don't have lineNo, fetch it from BC first using filter (systemId doesn't work in URL for PATCH)
      if (journalTemplateName && journalBatchName && !lineNo && id) {
        console.log('🔍 Fetching lineNo and ETag from BC for journal line:', id);

        // Use filter to find the line by systemId
        const filterEndpoint = `/companies(${this.companyId})/jobJournalLines?$filter=id eq ${id}&$select=lineNo,journalTemplateName,journalBatchName`;
        const result = await this.callBCApi(filterEndpoint);

        if (result.value && result.value.length > 0) {
          finalLineNo = result.value[0].lineNo;
          etag = result.value[0]['@odata.etag']; // Capture ETag for concurrency control
          console.log('✅ Got lineNo from BC:', finalLineNo, 'ETag:', etag ? 'present' : 'missing');
        } else {
          console.error('❌ Could not find journal line in BC with id:', id);
          throw new Error(`Journal line not found in BC: ${id}`);
        }
      }

      // Use composite keys if available
      if (journalTemplateName && journalBatchName && finalLineNo) {
        endpoint = `/companies(${this.companyId})/jobJournalLines(journalTemplateName='${journalTemplateName}',journalBatchName='${journalBatchName}',lineNo=${finalLineNo})`;
      } else {
        // Fallback to systemId (may not work with all BC versions)
        endpoint = `/companies(${this.companyId})/jobJournalLines(${id})`;
      }

      // Prepare headers with ETag if available
      const headers: any = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      };

      if (etag) {
        headers['If-Match'] = etag; // Required for concurrency control
        console.log('📌 Using ETag for PATCH:', etag);
      }

      const data = await this.callBCApi(endpoint, {
        method: 'PATCH',
        body: JSON.stringify(updateData),
        headers
      });
      return data;
    } catch (error) {
      console.error('BC Update Job Journal Line error:', error);
      throw error;
    }
  }

  async deleteJobJournalLine(journalId: string, compositeKeys?: { journalTemplateName: string; journalBatchName: string; lineNo: number }): Promise<void> {
    try {
      // 🗑️ Delete Job Journal Line
      // BC requires composite keys for DELETE operations
      let endpoint;
      let finalCompositeKeys = compositeKeys;

      // If we don't have composite keys, fetch them from BC first
      if (!compositeKeys && journalId) {
        console.log('🔍 Fetching composite keys for deletion:', journalId);
        const filterEndpoint = `/companies(${this.companyId})/jobJournalLines?$filter=id eq ${journalId}&$select=lineNo,journalTemplateName,journalBatchName`;
        const result = await this.callBCApi(filterEndpoint);

        if (result.value && result.value.length > 0) {
          const line = result.value[0];
          finalCompositeKeys = {
            journalTemplateName: line.journalTemplateName,
            journalBatchName: line.journalBatchName,
            lineNo: line.lineNo
          };
          console.log('✅ Got composite keys for deletion');
        }
      }

      if (finalCompositeKeys) {
        endpoint = `/companies(${this.companyId})/jobJournalLines(journalTemplateName='${finalCompositeKeys.journalTemplateName}',journalBatchName='${finalCompositeKeys.journalBatchName}',lineNo=${finalCompositeKeys.lineNo})`;
      } else {
        // Fallback to systemId (may not work with all BC versions)
        console.warn('⚠️  Using systemId fallback for DELETE - this may fail');
        endpoint = `/companies(${this.companyId})/jobJournalLines(${journalId})`;
      }

      await this.callBCApi(endpoint, {
        method: 'DELETE'
      });
    } catch (error) {
      console.error('BC Delete Job Journal Line error:', error);
      throw error;
    }
  }

  async createTimeEntry(timeEntry: any): Promise<any> {
    try {
      const endpoint = `/companies(${this.companyId})/timeEntries`;
      const data = await this.callBCApi(endpoint, {
        method: 'POST',
        body: JSON.stringify(timeEntry)
      });
      return data;
    } catch (error) {
      console.error('BC Create Time Entry error:', error);
      throw error;
    }
  }

  async postJobJournalBatch(batchName: string): Promise<any> {
    try {
      // 📮 POST Job Journal Batch (hace las entries inmutables)
      const endpoint = `/companies(${this.companyId})/jobJournalBatches('${batchName}')/Microsoft.NAV.post`;
      const data = await this.callBCApi(endpoint, {
        method: 'POST'
      });
      return data;
    } catch (error) {
      console.error('BC Post Job Journal Batch error:', error);
      throw error;
    }
  }

  async getTimeEntries(resourceNo?: string, dateFrom?: string, dateTo?: string): Promise<any[]> {
    try {
      let endpoint = `/companies(${this.companyId})/timeEntries`;

      const filters = [];
      if (resourceNo) filters.push(`resourceNo eq '${resourceNo}'`);
      if (dateFrom) filters.push(`date ge ${dateFrom}`);
      if (dateTo) filters.push(`date le ${dateTo}`);

      if (filters.length > 0) {
        endpoint += `?$filter=${filters.join(' and ')}`;
      }

      const data = await this.callBCApi(endpoint);
      return data.value || [];
    } catch (error) {
      console.error('BC Time Entries error:', error);
      return [];
    }
  }

  async getJobJournalLineStatus(journalId: string): Promise<{ approvalStatus?: string; comments?: string } | null> {
    try {
      // Get specific Job Journal Line by systemId
      const endpoint = `/companies(${this.companyId})/jobJournalLines(${journalId})`;
      const data = await this.callBCApi(endpoint);

      return {
        approvalStatus: data.approvalStatus || 'pending',
        comments: data.comments || ''
      };
    } catch (error) {
      console.error('BC Get Job Journal Line Status error:', error);
      return null;
    }
  }

  async getJobJournalLinesStatus(journalIds: string[]): Promise<Map<string, { approvalStatus: string; comments: string }>> {
    const results = new Map<string, { approvalStatus: string; comments: string }>();

    if (journalIds.length === 0) return results;

    try {
      // Build filter for multiple IDs: id eq 'xxx' or id eq 'yyy'
      const filter = journalIds.map(id => `id eq ${id}`).join(' or ');
      const endpoint = `/companies(${this.companyId})/jobJournalLines?$filter=${filter}&$select=id,approvalStatus,comments`;

      const data = await this.callBCApi(endpoint);

      if (data.value && Array.isArray(data.value)) {
        data.value.forEach((line: any) => {
          results.set(line.id, {
            approvalStatus: line.approvalStatus || 'pending',
            comments: line.comments || ''
          });
        });
      }

      return results;
    } catch (error) {
      console.error('BC Get Job Journal Lines Status error:', error);
      return results;
    }
  }
}