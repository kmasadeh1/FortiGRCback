import { authenticateRequest } from "@/lib/authGuard";
import { calculateRiskScore } from "@/lib/riskScoring";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { checkRbac } from "@/app/api/utils/rbac";

const VALID_CAPABILITIES = [
  "Architecture & Portfolio",
  "Development",
  "Delivery",
  "Operations",
  "Fundamental Capabilities",
  "National Cyber Responsibility",
];

/**
 * PUT /api/risks/[id]
 *
 * Updates an existing risk record by ID.
 * Recalculates quantitative_score and severity_level if likelihood/impact change.
 * Requires: Authorization: Bearer <access_token>
 */
export async function PUT(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Risk Manager");
    if (!hasPermission) {
      return corsResponse({ error: "Access Denied: You do not have the required permissions (Admin/Risk Manager)." }, 403);
    }

    const { id } = await context.params;  // Next.js 15: params is a Promise

    if (!id) {
      return corsResponse({ error: "Missing risk ID in URL" }, 400);
    }

    const body = await request.json();
    const { title, jncsf_capability, likelihood, impact } = body;

    const updates = {};

    if (title !== undefined) {
      if (typeof title !== "string" || title.trim().length === 0) {
        return corsResponse({ error: "title must be a non-empty string." }, 400);
      }
      updates.title = title.trim();
    }

    if (jncsf_capability !== undefined) {
      if (!VALID_CAPABILITIES.includes(jncsf_capability)) {
        return corsResponse(
          { error: `jncsf_capability must be one of: ${VALID_CAPABILITIES.join(", ")}.` },
          400
        );
      }
      updates.jncsf_capability = jncsf_capability;
    }

    // If either likelihood or impact is provided, recalculate score server-side
    if (likelihood !== undefined || impact !== undefined) {
      let finalLikelihood = likelihood;
      let finalImpact = impact;

      // Fetch the existing values if only one side changed
      if (finalLikelihood === undefined || finalImpact === undefined) {
        const { data: existing, error: fetchErr } = await client
          .from("risks")
          .select("likelihood, impact")
          .eq("id", id)
          .single();

        if (fetchErr || !existing) {
          return corsResponse({ error: "Risk not found or failed to fetch for recalculation." }, 404);
        }

        if (finalLikelihood === undefined) finalLikelihood = existing.likelihood;
        if (finalImpact === undefined) finalImpact = existing.impact;
      }

      if (finalLikelihood < 1 || finalLikelihood > 5 || finalImpact < 1 || finalImpact > 5) {
        return corsResponse({ error: "likelihood and impact must be integers between 1 and 5." }, 400);
      }

      const { score, severity_level } = calculateRiskScore(finalLikelihood, finalImpact);

      if (isNaN(score)) {
        return corsResponse({ error: "Invalid likelihood or impact values." }, 400);
      }

      updates.likelihood = finalLikelihood;
      updates.impact = finalImpact;
      updates.quantitative_score = score;
      updates.severity_level = severity_level;
    }

    if (Object.keys(updates).length === 0) {
      return corsResponse({ error: "No valid fields provided to update." }, 400);
    }

    const { data, error } = await client
      .from("risks")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      return corsResponse({ success: false, error: error.message }, 500);
    }

    // Write audit log (non-blocking)
    const ipAddress =
      request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      "unknown";

    client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "UPDATED_RISK",
        table_name: "risks",
        record_id: data.id,
        ip_address: ipAddress,
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log failed:", auditErr);
      });

    return new Response(JSON.stringify(data), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * DELETE /api/risks/[id]
 *
 * Permanently deletes a risk record by ID.
 * Requires: Authorization: Bearer <access_token>
 */
export async function DELETE(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Risk Manager");
    if (!hasPermission) {
      return corsResponse({ error: "Access Denied: You do not have the required permissions (Admin/Risk Manager)." }, 403);
    }

    const { id } = await context.params;  // Next.js 15: params is a Promise

    if (!id) {
      return corsResponse({ error: "Missing risk ID in URL" }, 400);
    }

    const { error } = await client
      .from("risks")
      .delete()
      .eq("id", id);

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      return corsResponse({ success: false, error: error.message }, 500);
    }

    // Write audit log (non-blocking)
    const ipAddress =
      request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      "unknown";

    client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "DELETED_RISK",
        table_name: "risks",
        record_id: id,
        ip_address: ipAddress,
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log failed:", auditErr);
      });

    return new Response(
      JSON.stringify({ success: true, message: `Risk ${id} deleted successfully.` }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/risks/[id]
 * Handles CORS preflight for PUT and DELETE requests.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
