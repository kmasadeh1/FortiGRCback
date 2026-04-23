import { NextResponse } from "next/server";
import { getSupabase } from "@/lib/supabaseClient";
import { createRateLimiter } from "@/lib/rateLimiter";

// Rate limit: 5 signup attempts per 60 seconds per IP
const limiter = createRateLimiter({ maxRequests: 5, windowMs: 60_000 });

// Server-side password policy (mirrors Supabase dashboard config)
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_REGEX = {
  uppercase: /[A-Z]/,
  lowercase: /[a-z]/,
  digit: /[0-9]/,
  special: /[^A-Za-z0-9]/,
};

/**
 * POST /api/auth/signup
 *
 * Creates a new user via Supabase Auth.
 *
 * Request body (JSON):
 *   - email    (string, required)
 *   - password (string, required — min 12 chars, uppercase, lowercase, digit, special)
 *
 * Returns the newly created user object.
 * Note: If email confirmation is enabled (recommended), the user must
 * verify their email before they can sign in.
 */
export async function POST(request) {
  try {
    // --- Rate limiting -------------------------------------------------------
    const { allowed, remaining, retryAfterMs } = limiter.check(request);
    if (!allowed) {
      return NextResponse.json(
        { error: "Too many signup attempts. Please try again later." },
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
    const errors = [];

    if (!email || typeof email !== "string" || email.trim().length === 0) {
      errors.push("email is required and must be a valid email address.");
    }

    if (!password || typeof password !== "string") {
      errors.push("password is required.");
    } else {
      if (password.length < PASSWORD_MIN_LENGTH) {
        errors.push(
          `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
        );
      }
      if (!PASSWORD_REGEX.uppercase.test(password)) {
        errors.push("Password must contain at least one uppercase letter.");
      }
      if (!PASSWORD_REGEX.lowercase.test(password)) {
        errors.push("Password must contain at least one lowercase letter.");
      }
      if (!PASSWORD_REGEX.digit.test(password)) {
        errors.push("Password must contain at least one digit.");
      }
      if (!PASSWORD_REGEX.special.test(password)) {
        errors.push("Password must contain at least one special character.");
      }
    }

    if (errors.length > 0) {
      return NextResponse.json(
        { error: "Validation failed", details: errors },
        { status: 400 }
      );
    }

    // --- Create user via Supabase Auth --------------------------------------
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.signUp({
      email: email.trim(),
      password,
    });

    if (error) {
      console.error("Supabase signup error:", error);
      return NextResponse.json(
        { error: "Signup failed", details: error.message },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        message:
          "Signup successful. Please check your email to confirm your account.",
        user: {
          id: data.user?.id,
          email: data.user?.email,
        },
      },
      {
        status: 201,
        headers: {
          "X-RateLimit-Remaining": String(remaining),
        },
      }
    );
  } catch (err) {
    console.error("Unexpected error in POST /api/auth/signup:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
