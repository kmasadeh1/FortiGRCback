import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight } from "@/lib/cors";

export async function GET(request) {
  const auth = await authenticateRequest(request);
  if (auth.error) return auth.error;
  const { client, user } = auth;

  const { data, error } = await client
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .maybeSingle();

  if (error) {
    return corsResponse({ success: false, error: error.message }, 500);
  }

  if (!data) {
    return corsResponse({ role: "user" }, 200);
  }

  return corsResponse({ role: data.role }, 200);
}

export function OPTIONS() {
  return handleCORSPreflight();
}
