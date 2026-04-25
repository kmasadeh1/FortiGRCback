import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_PRINCIPLES = [
  "Strategic",
  "Enterprise Driven",
  "Livable",
  "Economical",
  "Capability Based",
  "Trustable",
];

// How many recent control changes to surface in the response
const RECENT_CHANGES_LIMIT = 10;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Calculates a percentage rounded to one decimal place.
 * Returns 0 when the denominator is 0 to avoid division-by-zero.
 *
 * @param {number} numerator
 * @param {number} denominator
 * @returns {number}
 */
function toPercent(numerator, denominator) {
  if (denominator === 0) return 0;
  return Math.round((numerator / denominator) * 1000) / 10;
}

/**
 * Derives a human-readable compliance status label from a percentage.
 *
 * @param {number} pct - 0–100
 * @returns {"Non-Compliant"|"Partial"|"Compliant"}
 */
function complianceLabel(pct) {
  if (pct >= 80) return "Compliant";
  if (pct >= 40) return "Partial";
  return "Non-Compliant";
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

// ─── GET /api/compliance ──────────────────────────────────────────────────────

/**
 * Returns a full compliance overview for the authenticated user.
 *
 * Response shape:
 * {
 *   overall_score:   number   // 0–100 (percentage of compliant controls)
 *   overall_status:  string   // "Compliant" | "Partial" | "Non-Compliant"
 *   total_controls:  number
 *   compliant_count: number
 *   domain_scores: [
 *     {
 *       principle:       string,
 *       total:           number,
 *       compliant:       number,
 *       score:           number,   // 0–100
 *       status:          string
 *     }
 *   ],
 *   recent_changes: [             // last N updated/created controls
 *     {
 *       id, control_name, is_compliant, select_principle,
 *       risk_title, created_at
 *     }
 *   ]
 * }
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client } = auth;

    // ── 1. Fetch all controls (RLS scopes to this user's data) ────────────────
    const { data: controls, error: fetchErr } = await client
      .from("compliance_controls")
      .select(
        "id, control_name, is_compliant, select_principle, created_at, risks(title)"
      )
      .order("created_at", { ascending: false });

    if (fetchErr) {
      console.error("🔥 GET /api/compliance — fetch error:", fetchErr);
      return corsResponse(
        { error: "Failed to fetch compliance data", details: fetchErr.message },
        500
      );
    }

    const total = controls.length;
    const compliantCount = controls.filter((c) => c.is_compliant).length;

    // ── 2. Overall score (server-side calculation) ────────────────────────────
    const overallScore = toPercent(compliantCount, total);
    const overallStatus = complianceLabel(overallScore);

    // ── 3. Per-principle (domain) breakdown ───────────────────────────────────
    //
    // Group every control by its select_principle, then compute the compliance
    // percentage for each group. Unknown principles are bucketed as "Other".
    const principleMap = {};

    for (const ctrl of controls) {
      const key = VALID_PRINCIPLES.includes(ctrl.select_principle)
        ? ctrl.select_principle
        : "Other";

      if (!principleMap[key]) {
        principleMap[key] = { total: 0, compliant: 0 };
      }
      principleMap[key].total += 1;
      if (ctrl.is_compliant) principleMap[key].compliant += 1;
    }

    const domainScores = Object.entries(principleMap).map(
      ([principle, { total: t, compliant: c }]) => {
        const score = toPercent(c, t);
        return {
          principle,
          total: t,
          compliant: c,
          score,
          status: complianceLabel(score),
        };
      }
    );

    // Sort by score descending so the frontend can render a ranked list directly
    domainScores.sort((a, b) => b.score - a.score);

    // ── 4. Recent changes ─────────────────────────────────────────────────────
    //
    // The controls array is already sorted newest-first; just flatten the
    // nested risk join and slice to the limit.
    const recentChanges = controls.slice(0, RECENT_CHANGES_LIMIT).map(
      ({ risks, ...rest }) => ({
        ...rest,
        risk_title: risks?.title ?? null,
      })
    );

    // ── 5. Build and return the consolidated payload ──────────────────────────
    const payload = {
      overall_score: overallScore,
      overall_status: overallStatus,
      total_controls: total,
      compliant_count: compliantCount,
      domain_scores: domainScores,
      recent_changes: recentChanges,
    };

    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/compliance — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── POST /api/compliance ─────────────────────────────────────────────────────

/**
 * Creates a new compliance control linked to an existing risk.
 *
 * Expected JSON body:
 * {
 *   "risk_id":          string  (required, UUID of an existing risk)
 *   "control_name":     string  (required, non-empty)
 *   "select_principle": string  (required, one of the six S.E.L.E.C.T values)
 *   "is_compliant":     boolean (required)
 *   "jncf_mapping_id":  string  (optional, UUID of a jncf_controls row)
 * }
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client, user } = auth;

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

    const { risk_id, control_name, select_principle, is_compliant, jncf_mapping_id } =
      body;

    // ── Validate ─────────────────────────────────────────────────────────────

    const errors = [];

    if (!risk_id || typeof risk_id !== "string" || risk_id.trim().length === 0) {
      errors.push("risk_id is required and must be a valid UUID string.");
    }

    if (
      !control_name ||
      typeof control_name !== "string" ||
      control_name.trim().length === 0
    ) {
      errors.push("control_name is required and must be a non-empty string.");
    }

    if (!select_principle || !VALID_PRINCIPLES.includes(select_principle)) {
      errors.push(
        `select_principle is required and must be one of: ${VALID_PRINCIPLES.join(", ")}.`
      );
    }

    if (typeof is_compliant !== "boolean") {
      errors.push("is_compliant is required and must be a boolean.");
    }

    if (jncf_mapping_id !== undefined && jncf_mapping_id !== null) {
      if (
        typeof jncf_mapping_id !== "string" ||
        jncf_mapping_id.trim().length === 0
      ) {
        errors.push("jncf_mapping_id must be a valid UUID string when provided.");
      }
    }

    if (errors.length > 0) {
      return corsResponse({ error: "Validation failed", details: errors }, 400);
    }

    // ── Insert ────────────────────────────────────────────────────────────────

    const { data, error: insertErr } = await client
      .from("compliance_controls")
      .insert({
        risk_id: risk_id.trim(),
        control_name: control_name.trim(),
        select_principle,
        is_compliant,
        jncf_mapping_id: jncf_mapping_id ? jncf_mapping_id.trim() : null,
      })
      .select()
      .maybeSingle();

    if (insertErr) {
      console.error("🔥 POST /api/compliance — insert error:", insertErr);

      if (insertErr.code === "23503") {
        const detail = insertErr.message.includes("jncf_mapping_id")
          ? "The referenced JNCF control does not exist."
          : "The referenced risk does not exist.";
        return corsResponse({ error: "Foreign key violation", details: detail }, 400);
      }

      return corsResponse(
        { error: "Failed to create compliance control", details: insertErr.message },
        500
      );
    }

    if (!data) {
      return corsResponse(
        { error: "Failed to create compliance control", details: "No record returned after insert." },
        500
      );
    }

    // ── Audit log (non-blocking) ─────────────────────────────────────────────

    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "CREATED_CONTROL",
        table_name: "compliance_controls",
        record_id: data.id,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    return new Response(JSON.stringify(data), {
      status: 201,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 POST /api/compliance — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/compliance ──────────────────────────────────────────────────

/**
 * Handles CORS preflight requests from the browser before POST.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
