import { NextResponse } from "next/server";
import { getSupabase } from "@/lib/supabaseClient";
import { authenticateRequest } from "@/lib/authGuard";

/**
 * POST /api/auth/logout
 *
 * Signs out the current user by invalidating their Supabase session.
 * Requires a valid JWT in the Authorization header.
 */
export async function POST(request) {
  try {
    // --- Verify the user is authenticated -----------------------------------
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;

    // --- Sign out via Supabase Auth -----------------------------------------
    const supabase = getSupabase();
    const { error } = await supabase.auth.signOut();

    if (error) {
      console.error("Supabase signOut error:", error);
      return NextResponse.json(
        { error: "Logout failed", details: error.message },
        { status: 500 }
      );
    }

    return NextResponse.json(
      { message: "Logged out successfully." },
      { status: 200 }
    );
  } catch (err) {
    console.error("Unexpected error in POST /api/auth/logout:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
