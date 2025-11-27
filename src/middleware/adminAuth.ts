import { NextRequest, NextResponse } from 'next/server';
import { validateAdminAuth } from '@/lib/auth';

/**
 * Middleware to protect admin routes
 * Validates JWT token and ensures admin is authenticated
 */
export function withAdminAuth(
  handler: (request: NextRequest) => Promise<NextResponse>
): (request: NextRequest) => Promise<NextResponse> {
  return async (request: NextRequest) => {
    // Validate authentication
    const adminData = validateAdminAuth(request);

    if (!adminData) {
      return NextResponse.json(
        { error: 'Unauthorized - Invalid or missing authentication token' },
        { status: 401 }
      );
    }

    // Add admin data to request headers for use in handlers
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-admin-user-id', adminData.userId);
    requestHeaders.set('x-admin-username', adminData.username);

    // Create a new request with modified headers
    const modifiedRequest = new NextRequest(request, {
      headers: requestHeaders,
    });

    // Call the actual handler
    return handler(modifiedRequest);
  };
}

/**
 * Helper to extract admin data from request headers
 * (set by withAdminAuth middleware)
 */
export function getAdminDataFromRequest(request: NextRequest) {
  return {
    userId: request.headers.get('x-admin-user-id'),
    username: request.headers.get('x-admin-username'),
  };
}
