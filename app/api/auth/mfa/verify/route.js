import { NextResponse } from "next/server";
import { createAuthenticatedClient } from "@/lib/supabaseClient";
import { createRateLimiter } from "@/lib/rateLimiter";

// Rate limit: 5 MFA attempts per 60 seconds per IP
const limiter = createRateLimiter({ maxRequests: 5, windowMs: 60_000 });

/**
 * POST /api/auth/mfa/verify
 *
 * Verifies a TOTP code for multi-factor authentication.
 *
 * Request body (JSON):
 *   - factor_id (string, required — the MFA factor ID from the login response)
 *   - code      (string, required — the 6-digit TOTP code)
 *
 * Headers:
 *   - Authorization: Bearer <access_token>  (from the login response)
 *
 * Returns the verified session on success.
 */
export async function POST(request) {
  try {
    // --- Rate limiting -------------------------------------------------------
    const { allowed, remaining, retryAfterMs } = limiter.check(request);
    if (!allowed) {
      return NextResponse.json(
        { error: "Too many MFA attempts. Please try again later." },
        {
          status: 429,
          headers: {
            "Retry-After": String(Math.ceil(retryAfterMs / 1000)),
            "X-RateLimit-Remaining": "0",
          },
        }
      );
    }

    // --- Validate Authorization header --------------------------------------
    const authHeader = request.headers.get("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return NextResponse.json(
        { error: "Missing or invalid authorization header" },
        { status: 401 }
      );
    }

    const token = authHeader.split(" ")[1];

    // --- Parse body ----------------------------------------------------------
    const body = await request.json();
    const { factor_id, code } = body;

    const errors = [];
    if (!factor_id || typeof factor_id !== "string") {
      errors.push("factor_id is required.");
    }
    if (!code || typeof code !== "string" || !/^\d{6}$/.test(code)) {
      errors.push("code is required and must be a 6-digit string.");
    }
    if (errors.length > 0) {
      return NextResponse.json(
        { error: "Validation failed", details: errors },
        { status: 400 }
      );
    }

    // --- Create an MFA challenge and verify ---------------------------------
    const authedClient = createAuthenticatedClient(token);

    const { data: challengeData, error: challengeError } =
      await authedClient.auth.mfa.challenge({ factorId: factor_id });

    if (challengeError) {
      console.error("MFA challenge error:", challengeError);
      return NextResponse.json(
        { error: "MFA challenge failed", details: challengeError.message },
        { status: 400 }
      );
    }

    const { data: verifyData, error: verifyError } =
      await authedClient.auth.mfa.verify({
        factorId: factor_id,
        challengeId: challengeData.id,
        code,
      });

    if (verifyError) {
      console.error("MFA verify error:", verifyError);
      return NextResponse.json(
        { error: "Invalid TOTP code", details: verifyError.message },
        { status: 401 }
      );
    }

    return NextResponse.json(
      {
        message: "MFA verification successful.",
        session: {
          access_token: verifyData.session?.access_token,
          refresh_token: verifyData.session?.refresh_token,
          expires_in: verifyData.session?.expires_in,
          token_type: verifyData.session?.token_type,
        },
      },
      {
        status: 200,
        headers: { "X-RateLimit-Remaining": String(remaining) },
      }
    );
  } catch (err) {
    console.error("Unexpected error in POST /api/auth/mfa/verify:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
