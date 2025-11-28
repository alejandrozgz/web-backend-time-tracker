import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { comparePassword, generateToken } from '@/lib/auth';
import { logger } from '@/lib/logger';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { username, password } = body;

    // Validate input
    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      );
    }

    logger.info('Admin login attempt', { username });

    // Query admin_users table
    const { data: adminUser, error: queryError } = await supabaseAdmin
      .from('admin_users')
      .select('id, username, password_hash, is_active')
      .eq('username', username)
      .single();

    if (queryError || !adminUser) {
      logger.warn('Admin login failed - user not found', { username });
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Check if admin is active
    if (!adminUser.is_active) {
      logger.warn('Admin login failed - account inactive', { username });
      return NextResponse.json(
        { error: 'Account is inactive' },
        { status: 403 }
      );
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, adminUser.password_hash);

    if (!isPasswordValid) {
      logger.warn('Admin login failed - invalid password', { username });
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Update last_login_at
    await supabaseAdmin
      .from('admin_users')
      .update({ last_login_at: new Date().toISOString() })
      .eq('id', adminUser.id);

    // Generate JWT token
    const token = generateToken(adminUser.id, adminUser.username);

    logger.info('Admin login successful', { username, userId: adminUser.id });

    return NextResponse.json({
      success: true,
      token,
      user: {
        id: adminUser.id,
        username: adminUser.username
      }
    });

  } catch (error) {
    logger.error('Admin login error', { error });
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}
