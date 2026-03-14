import { NextRequest } from 'next/server';

export interface PlanningTokenPayload {
  tenantId: string;
  companyId: string;
  resourceNo: string;
  displayName: string;
  role?: string;
  entryMode?: string;
  jobJournalBatch?: string;
  exp?: number;
}

export function decodeToken(request: NextRequest): PlanningTokenPayload | null {
  const authHeader = request.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    return JSON.parse(Buffer.from(token, 'base64').toString()) as PlanningTokenPayload;
  } catch {
    return null;
  }
}

export function requirePMRole(request: NextRequest): PlanningTokenPayload {
  const payload = decodeToken(request);
  if (!payload) throw new Error('UNAUTHORIZED');
  if (payload.role !== 'pm') throw new Error('FORBIDDEN');
  return payload;
}
