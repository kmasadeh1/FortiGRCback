import { NextResponse } from "next/server";
import { getSupabase, createAuthenticatedClient } from "@/lib/supabaseClient";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Decodes the payload section of a JWT without verifying the signature.
 * Verification is handled by Supabase; we just need to read claims.
 *
 * @param {string} token
 * @returns {object|null}
 */
function decodeJwtPayload(token) {
  try {
    const base64Payload = token.split(".")[1];
    if (!base64Payload) return null;
    // Buffer.from handles both base64 and base64url (Node 18+)
    return JSON.parse(Buffer.from(base64Payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Authenticates an incoming API request using the Supabase JWT
 * from the `Authorization: Bearer <token>` header.
 *
 * On success, returns `{ user, client, aal }` where:
 *   - `user`   — the verified Supabase auth user object
 *   - `client` — a Supabase client scoped to that user (RLS-aware)
 *   - `aal`    — the Authenticator Assurance Level from the JWT ('aal1' | 'aal2')
 *
 * On failure, returns `{ error }` containing a ready-to-return NextResponse.
 * Callers must propagate it immediately:
 * ```js
 * const auth = await authenticateRequest(request);
 * if (auth.error) return auth.error;
 * const { user, client } = auth;
 * ```
 *
 * MFA handling:
 *   If the user has verified MFA factors enrolled but the current session was
 *   established with only a password (aal1), this function returns a 401 with
 *   `{ code: "MFA_REQUIRED" }` so the frontend can redirect to the MFA challenge
 *   screen rather than showing a generic error.
 *
 * @param {Request} request — the incoming Next.js route handler request
 * @returns {Promise<{ user?: object, client?: object, aal?: string, error?: NextResponse }>}
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

  // ── Step 1: Validate the JWT against Supabase Auth ───────────────────────
  const supabase = getSupabase();
  const {
    data: { user },
    error: getUserError,
  } = await supabase.auth.getUser(token);

  if (getUserError || !user) {
    return {
      error: NextResponse.json(
        { error: "Invalid or expired token" },
        { status: 401 }
      ),
    };
  }

  // ── Step 2: Read the AAL claim from the JWT payload ──────────────────────
  //
  // Supabase embeds `aal` ('aal1' | 'aal2') in every access token:
  //   • aal1 — authenticated with password only
  //   • aal2 — authenticated with password + a verified MFA factor
  //
  // We decode the payload locally (no network call) to read this claim.
  const claims = decodeJwtPayload(token);
  const aal = claims?.aal ?? "aal1";

  // ── Step 3: MFA gate — only fires when the session is still at AAL1 ──────
  if (aal === "aal1") {
    // Create a temporary client scoped to this user so we can query their factors.
    const tempClient = createAuthenticatedClient(token);
    const { data: factorsData } = await tempClient.auth.mfa.listFactors();

    // If the user has at least one *verified* TOTP factor they must complete the
    // MFA challenge before we grant access.  Unverified (partially enrolled)
    // factors are ignored — they cannot be used to satisfy AAL2 anyway.
    const verifiedFactors = [
      ...(factorsData?.totp ?? []),
      ...(factorsData?.phone ?? []),
    ].filter((f) => f.status === "verified");

    if (verifiedFactors.length > 0) {
      return {
        error: NextResponse.json(
          {
            error: "Multi-factor authentication required",
            code: "MFA_REQUIRED",
            message:
              "Your account has MFA enabled. Please complete the MFA challenge to continue.",
          },
          { status: 401 }
        ),
      };
    }
  }

  // ── Step 4: All checks passed — return scoped client ─────────────────────
  const client = createAuthenticatedClient(token);

  return { user, client, aal };
}
