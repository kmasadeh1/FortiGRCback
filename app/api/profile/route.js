import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { createClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';

/**
 * GET /api/profile
 *
 * Fetches the currently authenticated user's profile data.
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    // 1. Get the auth header
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: "Missing or invalid token" }, { status: 401 });
    }
    const token = authHeader.replace('Bearer ', '');

    // 2. Initialize standard Supabase client
    const supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    );

    // 3. Verify the user
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { data, error } = await supabase
      .from("profiles")
      .select("full_name, avatar_url")
      .eq("id", user.id)
      .maybeSingle();

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      return corsResponse({ success: false, error: error.message }, 500);
    }

    if (!data) {
       return new Response(JSON.stringify({ id: user.id, full_name: "", role: "user", avatar_url: null }), { status: 200, headers: CORS_HEADERS });
    }

    // Attach their actual auth email for completeness
    const profileData = { ...data, email: user.email };

    return new Response(JSON.stringify(profileData), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * PUT /api/profile
 *
 * Updates the currently authenticated user's profile data.
 * Can handle JSON payload containing full_name or avatar_url.
 * Requires: Authorization: Bearer <access_token>
 */
export async function PUT(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client, user } = auth;

    let body;
    try {
      body = await request.json();
      console.log("📥 RECEIVED BODY:", body);
    } catch {
      return corsResponse({ error: "Invalid JSON payload." }, 400);
    }

    // Direct mapping to avoid "No valid fields" validation blocks
    const updatePayload = {
      full_name: body.full_name,
      avatar_url: body.avatar_url,
      updated_at: new Date().toISOString()
    };

    // Update the profile based on the authenticated user's ID
    const { data, error } = await client
      .from("profiles")
      .update(updatePayload)
      .eq("id", user.id)
      .select()
      .maybeSingle();

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      return corsResponse({ success: false, error: error.message }, 500);
    }
    
    if (!data) {
       return corsResponse({ success: false, error: "Profile not found" }, 404);
    }

    // Audit log (non-blocking)
    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
    client.from("audit_logs").insert({
      user_id: user.id,
      action: "UPDATED_PROFILE",
      table_name: "profiles",
      record_id: user.id,
      ip_address: ipAddress,
    }).then(({ error: auditErr }) => { if (auditErr) console.error("Audit log failed:", auditErr); });

    return new Response(JSON.stringify(data), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/profile
 * Handles CORS preflight for PUT requests.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
