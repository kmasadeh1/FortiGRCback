import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

/**
 * GET /api/framework/jncf
 *
 * Retrieves all JNCF domains and their nested JNCF controls.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    // Fetch domains joined with their controls
    const { data, error } = await client
      .from("jncf_domains")
      .select(`
        id, 
        domain_code, 
        title, 
        jncf_controls (
          id, 
          control_code, 
          description
        )
      `)
      .order("domain_code", { ascending: true });

    if (error) {
      console.error("Supabase select error [JNCF]:", error);
      return NextResponse.json(
        { error: "Failed to fetch JNCF framework data", details: error.message },
        { status: 500 }
      );
    }

    return NextResponse.json(data, { status: 200 });
  } catch (err) {
    console.error("Unexpected error in GET /api/framework/jncf:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
