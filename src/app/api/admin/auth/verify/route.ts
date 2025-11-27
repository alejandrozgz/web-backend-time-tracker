import { NextRequest, NextResponse } from 'next/server';
import { validateAdminAuth } from '@/lib/auth';

export async function GET(request: NextRequest) {
  try {
    const adminData = validateAdminAuth(request);

    if (!adminData) {
      return NextResponse.json(
        { error: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    return NextResponse.json({
      success: true,
      user: {
        id: adminData.userId,
        username: adminData.username
      }
    });

  } catch (error) {
    console.error('Error verifying admin token:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
