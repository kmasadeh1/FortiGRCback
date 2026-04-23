import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight } from "@/lib/cors";

/**
 * GET /api/assessments/history
 *
 * Fetches all completed assessments for the current authenticated user,
 * ordered by most recently completed first.
 *
 * Returns:
 * { history: [ { id, title, description, status, created_at, completed_at } ] }
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client } = auth;

    const { data, error } = await client
      .from("assessments")
      .select("id, title, status, created_at")
      .eq("status", "Completed")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("🔥 Failed to fetch assessment history:", error);
      return corsResponse({ error: "Failed to fetch assessment history.", details: error.message }, 500);
    }

    console.log("History Data:", data);

    return NextResponse.json({ history: data || [] }, { status: 200 });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/assessments/history
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
