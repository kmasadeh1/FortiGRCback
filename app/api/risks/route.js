import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { getSupabase } from "@/lib/supabaseClient";
import { calculateRiskScore } from "@/lib/riskScoring";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { checkRbac } from "@/app/api/utils/rbac";

// Valid values for the jncsf_capability_enum
const VALID_CAPABILITIES = [
  "Architecture & Portfolio",
  "Development",
  "Delivery",
  "Operations",
  "Fundamental Capabilities",
  "National Cyber Responsibility",
];

/**
 * GET /api/risks
 *
 * Returns all risks owned by the authenticated user (id and title only),
 * ordered newest-first.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    
    // Explicitly check for user session to debug authentication failures natively
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    
    const { client } = auth;

    const { data, error } = await client
      .from("risks")
      .select("id, title, quantitative_score, severity_level")
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return new Response(JSON.stringify(data), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * POST /api/risks
 *
 * Creates a new risk record explicitly passing likelihood and impact through
 * the risk scoring matrix logic rather than trusting client numbers.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    // authenticateRequest validates the Bearer JWT via supabase.auth.getUser()
    // DO NOT use getSession() here — it requires a cookie-based session which
    // does not exist in a Bearer token flow and will always return null server-side.
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    const body = await request.json();
    const { title, jncsf_capability, likelihood, impact } = body;

    const errors = [];

    if (!title || typeof title !== "string" || title.trim().length === 0) {
      errors.push("title is required and must be a non-empty string.");
    }

    if (!jncsf_capability || !VALID_CAPABILITIES.includes(jncsf_capability)) {
      errors.push(`jncsf_capability is required and must be one of: ${VALID_CAPABILITIES.join(", ")}.`);
    }

    const { score, severity_level } = calculateRiskScore(likelihood, impact);

    if (isNaN(score)) {
       errors.push("likelihood and impact must be valid integers between 1 and 5.");
    } else if (likelihood < 1 || likelihood > 5 || impact < 1 || impact > 5) {
       errors.push("likelihood and impact must be strictly between 1 and 5.");
    }

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    const { data, error } = await client
      .from("risks")
      .insert({
        title: title.trim(),
        jncsf_capability,
        likelihood,
        impact,
        quantitative_score: score,
        severity_level
      })
      .select()
      .maybeSingle();

    if (error || !data) {
      console.error("Supabase insert error:", error || "No data returned");
      return NextResponse.json({ error: "Failed to create risk", details: error?.message || "Unknown error" }, { status: 500 });
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "CREATED_RISK",
        table_name: "risks",
        record_id: data.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log insertion failed:", auditError);

    return new Response(JSON.stringify(data), { status: 201, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * PUT /api/risks
 *
 * Updates an existing risk record securely intercepting likelihood and impact updates
 * through the risk scoring matrix rather than trusting client numbers.
 */
export async function PUT(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Risk Manager");
    if (!hasPermission) {
      return NextResponse.json(
        { error: "Access Denied: You do not have the required permissions (Admin/Risk Manager)." },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { id, title, jncsf_capability, likelihood, impact } = body;

    if (!id || typeof id !== "string") {
      return NextResponse.json({ error: "Validation failed", details: ["id is required to update a risk."] }, { status: 400 });
    }

    const updates = {};
    if (title !== undefined) updates.title = title.trim();
    if (jncsf_capability !== undefined) {
      if (!VALID_CAPABILITIES.includes(jncsf_capability)) {
         return NextResponse.json({ error: "Validation failed", details: [`jncsf_capability must be one of: ${VALID_CAPABILITIES.join(", ")}.`] }, { status: 400 });
      }
      updates.jncsf_capability = jncsf_capability;
    }

    if (likelihood !== undefined || impact !== undefined) {
       // Fetch existing risk if one of them is missing to calculate the new score safely
       let finalLikelihood = likelihood;
       let finalImpact = impact;
       
       if (finalLikelihood === undefined || finalImpact === undefined) {
           const { data: existingRisk, error: fetchErr } = await client.from("risks").select("likelihood, impact").eq("id", id).maybeSingle();
           if (fetchErr || !existingRisk) return NextResponse.json({ error: "Failed to fetch existing risk to recalculate score." }, { status: 500 });
           
           if (finalLikelihood === undefined) finalLikelihood = existingRisk.likelihood;
           if (finalImpact === undefined) finalImpact = existingRisk.impact;
       }

       const { score, severity_level } = calculateRiskScore(finalLikelihood, finalImpact);

       if (isNaN(score)) {
          return NextResponse.json({ error: "Validation failed", details: ["likelihood and impact must be valid integers between 1 and 5."] }, { status: 400 });
       } else if (finalLikelihood < 1 || finalLikelihood > 5 || finalImpact < 1 || finalImpact > 5) {
          return NextResponse.json({ error: "Validation failed", details: ["likelihood and impact must be strictly between 1 and 5."] }, { status: 400 });
       }

       updates.likelihood = finalLikelihood;
       updates.impact = finalImpact;
       updates.quantitative_score = score;
       updates.severity_level = severity_level;
    }

    const { data, error } = await client
      .from("risks")
      .update(updates)
      .eq("id", id)
      .select()
      .maybeSingle();

    if (error) {
      console.error("Supabase update error:", error);
      return NextResponse.json({ error: "Failed to update risk", details: error.message }, { status: 500 });
    }
    
    if (!data) {
      return NextResponse.json({ error: "Risk not found or update failed." }, { status: 404 });
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "UPDATED_RISK",
        table_name: "risks",
        record_id: data.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log insertion failed:", auditError);

    return new Response(JSON.stringify(data), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/risks
 * Handles CORS preflight requests sent by the browser before POST/PUT.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
