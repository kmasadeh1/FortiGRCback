import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { createClient as createServerClient } from "@/lib/supabase/server";
import { authenticateRequest } from "@/lib/authGuard";
import { checkRbac } from "@/app/api/utils/rbac";
import { corsResponse, handleCORSPreflight } from "@/lib/cors";

const VALID_ROLES = ["user", "auditor", "risk manager", "admin", "super_admin"];

function getServiceClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
}

function getAdminClient() {
  return getServiceClient();
}

export async function GET(request) {
  const auth = await authenticateRequest(request);
  if (auth.error) return auth.error;

  const isAdmin = await checkRbac(auth.client, auth.user.id, "admin");
  if (!isAdmin) return corsResponse({ error: "Forbidden" }, 403);

  const serviceClient = getServiceClient();
  const { data, error } = await serviceClient
    .from("profiles")
    .select("id, full_name, email, role, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    console.error("GET /api/admin/users error:", error);
    return corsResponse({ error: error.message }, 500);
  }

  return corsResponse(data, 200);
}

export async function PATCH(request) {
  try {
    const supabase = await createServerClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', user.id).single();
    if (profile?.role !== 'super_admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

    const { userId, role, full_name } = await request.json();
    const adminClient = getAdminClient();

    const updates = {};
    if (role !== undefined) updates.role = role;
    if (full_name !== undefined) updates.full_name = full_name;

    const { error } = await adminClient.from('profiles').update(updates).eq('id', userId);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function DELETE(request) {
  try {
    const supabase = await createServerClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', user.id).single();
    if (profile?.role !== 'super_admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

    const { userId } = await request.json();

    if (userId === user.id) return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 });

    const adminClient = getAdminClient();

    // Delete from auth (cascades to profiles)
    const { error } = await adminClient.auth.admin.deleteUser(userId);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export function OPTIONS() {
  return handleCORSPreflight();
}
