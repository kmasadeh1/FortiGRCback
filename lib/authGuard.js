import { NextResponse } from "next/server";
import { getSupabase, createAuthenticatedClient } from "@/lib/supabaseClient";

/**
 * Authenticates an incoming API request using the Supabase JWT
 * from the `Authorization: Bearer <token>` header.
 *
 * On success, returns `{ user, client }` where:
 *   - `user`   — the verified Supabase auth user object
 *   - `client` — a Supabase client scoped to that user (RLS-aware)
 *
 * On failure, returns `{ error }` containing a ready-to-return NextResponse (401).
 *
 * Usage in a route handler:
 * ```js
 * const auth = await authenticateRequest(request);
 * if (auth.error) return auth.error;
 * const { user, client } = auth;
 * ```
 *
 * @param {Request} request — the incoming Next.js route handler request
 * @returns {Promise<{ user?: object, client?: object, error?: NextResponse }>}
 */
export async function authenticateRequest(request) {
  const authHeader = request.headers.get("authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return {
      error: NextResponse.json(
        { error: "Missing or invalid authorization header" },
        { status: 401 }
      ),
    };
  }

  const token = authHeader.split(" ")[1];

  if (!token || token.trim().length === 0) {
    return {
      error: NextResponse.json(
        { error: "Empty bearer token" },
        { status: 401 }
      ),
    };
  }

  // Validate the JWT against Supabase Auth
  const supabase = getSupabase();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !user) {
    return {
      error: NextResponse.json(
        { error: "Invalid or expired token" },
        { status: 401 }
      ),
    };
  }

  // Create a Supabase client scoped to this user for RLS
  const client = createAuthenticatedClient(token);

  return { user, client };
}
