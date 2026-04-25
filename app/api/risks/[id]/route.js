import { authenticateRequest } from "@/lib/authGuard";
import { calculateRiskScore } from "@/lib/riskScoring";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { checkRbac } from "@/app/api/utils/rbac";

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_CAPABILITIES = [
  "Architecture & Portfolio",
  "Development",
  "Delivery",
  "Operations",
  "Fundamental Capabilities",
  "National Cyber Responsibility",
];

const VALID_STATUSES = ["Open", "In Progress", "Mitigated"];

// Full column projection returned on every risk object
const RISK_SELECT_FIELDS = [
  "id",
  "title",
  "description",
  "jncsf_capability",
  "likelihood",
  "impact",
  "quantitative_score",
  "severity_level",
  "status",
  "created_at",
].join(", ");

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Strips any columns that must never be sent back to the client
 * (e.g. internal foreign keys). Keeps the surface clean and predictable.
 *
 * @param {object} risk - Raw row from Supabase
 * @returns {object}
 */
function sanitizeRisk(risk) {
  const { user_id, ...safe } = risk;
  return safe;
}

/**
 * Extracts the client IP from standard proxy headers.
 *
 * @param {Request} request
 * @returns {string}
 */
function getClientIp(request) {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    request.headers.get("x-real-ip")?.trim() ||
    "unknown"
  );
}

// ─── GET /api/risks/[id] ──────────────────────────────────────────────────────

/**
 * Returns a single risk by its UUID.
 *
 * URL: GET /api/risks/<uuid>
 * Requires: Authorization: Bearer <access_token>
 *
 * Responds:
 *   200 — risk object
 *   401 — unauthenticated
 *   404 — risk not found (or does not belong to this user)
 *   500 — server/database error
 */
export async function GET(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client } = auth;
    const { id } = await context.params; // Next.js 15: params is a Promise

    if (!id || typeof id !== "string") {
      return corsResponse({ error: "Missing or invalid risk ID in URL." }, 400);
    }

    const { data, error } = await client
      .from("risks")
      .select(RISK_SELECT_FIELDS)
      .eq("id", id)
      .maybeSingle(); // safe: returns null instead of throwing when not found

    if (error) {
      console.error(`🔥 GET /api/risks/${id} — Supabase error:`, error);
      return corsResponse(
        { error: "Failed to fetch risk", details: error.message },
        500
      );
    }

    if (!data) {
      return corsResponse(
        { error: "Risk not found or you do not have permission to view it." },
        404
      );
    }

    return new Response(JSON.stringify(sanitizeRisk(data)), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/risks/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── PUT /api/risks/[id] ──────────────────────────────────────────────────────

/**
 * Updates an existing risk record by ID.
 *
 * Expected JSON body (all fields optional — send only what changes):
 * {
 *   "title":            string  (optional, non-empty)
 *   "description":      string  (optional)
 *   "jncsf_capability": string  (optional, must be a valid JNCSF domain)
 *   "status":           string  (optional: 'Open' | 'In Progress' | 'Mitigated')
 *   "likelihood":       integer (optional, 1–5)
 *   "impact":           integer (optional, 1–5)
 * }
 *
 * Business logic (server-side):
 *   - If likelihood or impact is updated, the server fetches the other value
 *     (if not supplied) from the existing record, then recalculates
 *     quantitative_score (inherent_risk_score) and severity_level (risk_level).
 *   - The client must NEVER supply quantitative_score or severity_level directly.
 *
 * Requires:
 *   Authorization: Bearer <access_token>
 *   Role: Risk Manager or higher
 */
export async function PUT(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client, user } = auth;

    // ── RBAC: only Risk Manager or Admin may mutate risks ────────────────────

    const hasPermission = await checkRbac(client, user.id, "Risk Manager");
    if (!hasPermission) {
      return corsResponse(
        {
          error:
            "Access Denied: You do not have the required permissions (Risk Manager or Admin).",
        },
        403
      );
    }

    const { id } = await context.params; // Next.js 15: params is a Promise

    if (!id || typeof id !== "string") {
      return corsResponse({ error: "Missing or invalid risk ID in URL." }, 400);
    }

    // ── Parse body ───────────────────────────────────────────────────────────

    let body;
    try {
      body = await request.json();
    } catch {
      return corsResponse(
        { error: "Invalid request body", details: "Request body must be valid JSON." },
        400
      );
    }

    const { title, description, jncsf_capability, status, likelihood, impact } = body;

    // ── Validate each supplied field ─────────────────────────────────────────

    const validationErrors = [];

    if (title !== undefined) {
      if (typeof title !== "string" || title.trim().length === 0) {
        validationErrors.push("title must be a non-empty string.");
      } else if (title.trim().length > 255) {
        validationErrors.push("title must not exceed 255 characters.");
      }
    }

    if (description !== undefined && typeof description !== "string") {
      validationErrors.push("description must be a string when provided.");
    }

    if (jncsf_capability !== undefined && !VALID_CAPABILITIES.includes(jncsf_capability)) {
      validationErrors.push(
        `jncsf_capability must be one of: ${VALID_CAPABILITIES.join(", ")}.`
      );
    }

    if (status !== undefined && !VALID_STATUSES.includes(status)) {
      validationErrors.push(
        `status must be one of: ${VALID_STATUSES.join(", ")}.`
      );
    }

    // Validate likelihood / impact only when they are explicitly provided
    if (likelihood !== undefined) {
      const parsed = Number(likelihood);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 5) {
        validationErrors.push("likelihood must be an integer between 1 and 5.");
      }
    }

    if (impact !== undefined) {
      const parsed = Number(impact);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 5) {
        validationErrors.push("impact must be an integer between 1 and 5.");
      }
    }

    if (validationErrors.length > 0) {
      return corsResponse(
        { error: "Validation failed", details: validationErrors },
        400
      );
    }

    // ── Build update object ───────────────────────────────────────────────────

    const updates = {};

    if (title !== undefined)            updates.title = title.trim();
    if (description !== undefined)      updates.description = description.trim() || null;
    if (jncsf_capability !== undefined) updates.jncsf_capability = jncsf_capability;
    if (status !== undefined)           updates.status = status;

    // ── Scoring recalculation (server-side only) ──────────────────────────────

    if (likelihood !== undefined || impact !== undefined) {
      let finalLikelihood = likelihood !== undefined ? Number(likelihood) : undefined;
      let finalImpact = impact !== undefined ? Number(impact) : undefined;

      // If only one side changed, we need the existing value from the DB
      if (finalLikelihood === undefined || finalImpact === undefined) {
        const { data: existing, error: fetchErr } = await client
          .from("risks")
          .select("likelihood, impact")
          .eq("id", id)
          .maybeSingle();

        if (fetchErr) {
          console.error(`🔥 PUT /api/risks/${id} — Fetch for recalc failed:`, fetchErr);
          return corsResponse(
            { error: "Failed to fetch existing risk for score recalculation.", details: fetchErr.message },
            500
          );
        }

        if (!existing) {
          return corsResponse(
            { error: "Risk not found or you do not have permission to update it." },
            404
          );
        }

        if (finalLikelihood === undefined) finalLikelihood = existing.likelihood;
        if (finalImpact === undefined)     finalImpact     = existing.impact;
      }

      // Always recalculate server-side — never accept a score from the client
      const { score: inherent_risk_score, severity_level: risk_level } =
        calculateRiskScore(finalLikelihood, finalImpact);

      updates.likelihood          = finalLikelihood;
      updates.impact              = finalImpact;
      updates.quantitative_score  = inherent_risk_score;
      updates.severity_level      = risk_level;
    }

    // Reject empty payloads — nothing to update
    if (Object.keys(updates).length === 0) {
      return corsResponse(
        {
          error: "Validation failed",
          details: "No valid fields provided to update. Send at least one of: title, description, jncsf_capability, status, likelihood, impact.",
        },
        400
      );
    }

    // ── Persist update ────────────────────────────────────────────────────────

    const { data, error: updateError } = await client
      .from("risks")
      .update(updates)
      .eq("id", id)
      .select(RISK_SELECT_FIELDS)
      .maybeSingle(); // safe: returns null instead of throwing when not found

    if (updateError) {
      console.error(`🔥 PUT /api/risks/${id} — Supabase update error:`, updateError);
      return corsResponse(
        { error: "Failed to update risk", details: updateError.message },
        500
      );
    }

    if (!data) {
      return corsResponse(
        { error: "Risk not found or you do not have permission to update it." },
        404
      );
    }

    // ── Audit log (non-blocking) ─────────────────────────────────────────────

    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "UPDATED_RISK",
        table_name: "risks",
        record_id: data.id,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    return new Response(JSON.stringify(sanitizeRisk(data)), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 PUT /api/risks/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

/**
 * PATCH /api/risks/[id]
 *
 * Semantic alias for PUT — both accept partial payloads.
 * The frontend may use either verb; behaviour is identical.
 */
export const PATCH = PUT;

// ─── DELETE /api/risks/[id] ───────────────────────────────────────────────────

/**
 * Permanently deletes a risk record by ID.
 *
 * Requires:
 *   Authorization: Bearer <access_token>
 *   Role: Risk Manager or higher
 */
export async function DELETE(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client, user } = auth;

    // ── RBAC guard ────────────────────────────────────────────────────────────

    const hasPermission = await checkRbac(client, user.id, "Risk Manager");
    if (!hasPermission) {
      return corsResponse(
        {
          error:
            "Access Denied: You do not have the required permissions (Risk Manager or Admin).",
        },
        403
      );
    }

    const { id } = await context.params; // Next.js 15: params is a Promise

    if (!id || typeof id !== "string") {
      return corsResponse({ error: "Missing or invalid risk ID in URL." }, 400);
    }

    // ── Verify record exists before deletion (gives a clean 404 vs silent no-op) ──

    const { data: existing, error: checkErr } = await client
      .from("risks")
      .select("id")
      .eq("id", id)
      .maybeSingle();

    if (checkErr) {
      console.error(`🔥 DELETE /api/risks/${id} — Pre-check error:`, checkErr);
      return corsResponse(
        { error: "Failed to verify risk before deletion.", details: checkErr.message },
        500
      );
    }

    if (!existing) {
      return corsResponse(
        { error: "Risk not found or you do not have permission to delete it." },
        404
      );
    }

    // ── Execute deletion ─────────────────────────────────────────────────────

    const { error: deleteError } = await client
      .from("risks")
      .delete()
      .eq("id", id);

    if (deleteError) {
      console.error(`🔥 DELETE /api/risks/${id} — Supabase delete error:`, deleteError);
      return corsResponse(
        { error: "Failed to delete risk", details: deleteError.message },
        500
      );
    }

    // ── Audit log (non-blocking) ─────────────────────────────────────────────

    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "DELETED_RISK",
        table_name: "risks",
        record_id: id,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    return new Response(
      JSON.stringify({ success: true, message: `Risk ${id} deleted successfully.` }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 DELETE /api/risks/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/risks/[id] ──────────────────────────────────────────────────

/**
 * Handles CORS preflight requests for PUT, PATCH, and DELETE.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
