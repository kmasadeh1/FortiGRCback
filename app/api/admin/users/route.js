import { createClient } from "@supabase/supabase-js";
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
  const auth = await authenticateRequest(request);
  if (auth.error) return auth.error;

  const isAdmin = await checkRbac(auth.client, auth.user.id, "admin");
  if (!isAdmin) return corsResponse({ error: "Forbidden" }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return corsResponse({ error: "Invalid JSON payload" }, 400);
  }

  const { userId, role } = body;

  if (!userId || !role) {
    return corsResponse({ error: "userId and role are required" }, 400);
  }

  if (!VALID_ROLES.includes(role)) {
    return corsResponse(
      { error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}` },
      400
    );
  }

  // Only super_admin can assign admin or super_admin roles
  if (role === "admin" || role === "super_admin") {
    const isSuperAdmin = await checkRbac(auth.client, auth.user.id, "super_admin");
    if (!isSuperAdmin) {
      return corsResponse(
        { error: "Only super_admin can assign admin or super_admin roles" },
        403
      );
    }
  }

  const serviceClient = getServiceClient();
  const { data, error } = await serviceClient
    .from("profiles")
    .update({ role })
    .eq("id", userId)
    .select("id, full_name, email, role")
    .maybeSingle();

  if (error) {
    console.error("PATCH /api/admin/users error:", error);
    return corsResponse({ error: error.message }, 500);
  }

  if (!data) {
    return corsResponse({ error: "User not found" }, 404);
  }

  return corsResponse(data, 200);
}

export function OPTIONS() {
  return handleCORSPreflight();
}
