import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';
import { comparePassword, generateToken } from '@/lib/auth';

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

    console.log(`🔐 Admin login attempt for username: ${username}`);

    // Query admin_users table
    const { data: adminUser, error: queryError } = await supabaseAdmin
      .from('admin_users')
      .select('id, username, password_hash, is_active')
      .eq('username', username)
      .single();

    if (queryError || !adminUser) {
      console.log('❌ Admin user not found');
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Check if admin is active
    if (!adminUser.is_active) {
      console.log('❌ Admin user is inactive');
      return NextResponse.json(
        { error: 'Account is inactive' },
        { status: 403 }
      );
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, adminUser.password_hash);

    if (!isPasswordValid) {
      console.log('❌ Invalid password');
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

    console.log(`✅ Admin login successful for: ${username}`);

    return NextResponse.json({
      success: true,
      token,
      user: {
        id: adminUser.id,
        username: adminUser.username
      }
    });

  } catch (error) {
    console.error('Error during admin login:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown' },
      { status: 500 }
    );
  }
}
