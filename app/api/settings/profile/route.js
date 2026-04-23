import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/authGuard';

/**
 * GET /api/settings/profile
 * 
 * Retrieves the currently authenticated user's profile information
 * using Supabase auth metadata.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { user } = auth;

    // Retrieve fields from user metadata
    const metadata = user.user_metadata || {};
    const profile = {
      id: user.id,
      email: user.email,
      name: metadata.name || '',
      department: metadata.department || '',
      role: metadata.role || 'Auditor',
      theme: metadata.theme || 'dark'
    };

    return NextResponse.json(profile, { status: 200 });
  } catch (error) {
    console.error('API Error /settings/profile GET:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

/**
 * PUT /api/settings/profile
 * 
 * Updates the currently authenticated user's profile information
 * (name, department, theme, role) in the Supabase auth metadata.
 */
export async function PUT(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    // We get the raw token from the authorization header to set the session temporarily
    // if client.auth.updateUser fails without explicit session state
    const { client, user } = auth;
    
    const body = await request.json();
    const { name, department, theme, role } = body;

    // Update user metadata 
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (department !== undefined) updates.department = department;
    if (theme !== undefined) updates.theme = theme;
    if (role !== undefined) updates.role = role;

    // Explicitly set the session first so updateUser works on the server-side client
    const token = request.headers.get("authorization").split(" ")[1];
    await client.auth.setSession({ access_token: token, refresh_token: '' });

    const { data: updatedUser, error } = await client.auth.updateUser({
      data: updates
    });

    if (error) {
      throw new Error(`Failed to update profile: ${error.message}`);
    }

    // fallback to original user if updatedUser doesn't contain user root
    const usr = updatedUser?.user || user;
    const metadata = usr.user_metadata || {};
    const profile = {
      id: usr.id,
      email: usr.email,
      name: metadata.name || '',
      department: metadata.department || '',
      role: metadata.role || 'Auditor',
      theme: metadata.theme || 'dark'
    };

    return NextResponse.json({ message: 'Profile updated successfully', profile }, { status: 200 });
  } catch (error) {
    console.error('API Error /settings/profile PUT:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
