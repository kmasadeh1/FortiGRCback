import { NextResponse } from "next/server";
import { getSupabase } from "@/lib/supabaseClient";
import { createRateLimiter } from "@/lib/rateLimiter";

// Rate limit: 5 login attempts per 60 seconds per IP
const limiter = createRateLimiter({ maxRequests: 5, windowMs: 60_000 });

/**
 * POST /api/auth/login
 *
 * Authenticates a user via Supabase Auth using email + password.
 *
 * Request body (JSON):
 *   - email    (string, required)
 *   - password (string, required)
 *
 * Returns the session tokens (access_token, refresh_token) on success.
 * If MFA is enrolled, the response will include an `mfa_required` flag
 * and a `factors` array — the frontend must then call /api/auth/mfa/verify.
 */
export async function POST(request) {
  try {
    // --- Rate limiting -------------------------------------------------------
    const { allowed, remaining, retryAfterMs } = limiter.check(request);
    if (!allowed) {
      return NextResponse.json(
        { error: "Too many login attempts. Please try again later." },
        {
          status: 429,
          headers: {
            "Retry-After": String(Math.ceil(retryAfterMs / 1000)),
            "X-RateLimit-Remaining": "0",
          },
        }
      );
    }

    // --- Parse body ----------------------------------------------------------
    const body = await request.json();
    const { email, password } = body;

    // --- Validate fields -----------------------------------------------------
    if (!email || typeof email !== "string" || email.trim().length === 0) {
      return NextResponse.json(
        { error: "email is required." },
        { status: 400 }
      );
    }

    if (!password || typeof password !== "string" || password.length === 0) {
      return NextResponse.json(
        { error: "password is required." },
        { status: 400 }
      );
    }

    // --- Authenticate via Supabase Auth -------------------------------------
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password,
    });

    if (error) {
      // Intentionally vague message to avoid leaking whether the email exists
      console.error("Supabase login error:", error);
      return NextResponse.json(
        { error: "Invalid email or password." },
        { status: 401 }
      );
    }

    // --- Check if MFA is required -------------------------------------------
    // If the user has enrolled TOTP factors, require verification
    const {
      data: { factors },
    } = await supabase.auth.mfa.listFactors();

    const totpFactors = (factors || []).filter(
      (f) => f.factor_type === "totp" && f.status === "verified"
    );

    if (totpFactors.length > 0) {
      return NextResponse.json(
        {
          mfa_required: true,
          message: "MFA verification required. Submit a TOTP code.",
          factors: totpFactors.map((f) => ({
            id: f.id,
            friendly_name: f.friendly_name,
          })),
          // Still return the session so the frontend can use it
          // alongside the MFA challenge
          session: {
            access_token: data.session?.access_token,
            refresh_token: data.session?.refresh_token,
            expires_in: data.session?.expires_in,
          },
        },
        {
          status: 200,
          headers: { "X-RateLimit-Remaining": String(remaining) },
        }
      );
    }

    // --- Return session tokens -----------------------------------------------
    return NextResponse.json(
      {
        message: "Login successful.",
        session: {
          access_token: data.session?.access_token,
          refresh_token: data.session?.refresh_token,
          expires_in: data.session?.expires_in,
          token_type: data.session?.token_type,
        },
        user: {
          id: data.user?.id,
          email: data.user?.email,
        },
      },
      {
        status: 200,
        headers: { "X-RateLimit-Remaining": String(remaining) },
      }
    );
  } catch (err) {
    console.error("Unexpected error in POST /api/auth/login:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
