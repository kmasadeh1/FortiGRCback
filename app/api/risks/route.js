import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { calculateRiskScore } from "@/lib/riskScoring";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

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

const VALID_SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"];

// Columns the client is allowed to sort by (whitelist prevents SQL injection)
const SORTABLE_COLUMNS = [
  "created_at",
  "quantitative_score",
  "severity_level",
  "title",
  "status",
];

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
  // user_id is an internal ownership column — never expose it
  const { user_id, ...safe } = risk;
  return safe;
}

/**
 * Extracts the client IP from standard proxy headers.
 * Falls back to "unknown" when neither header is present.
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

// ─── GET /api/risks ───────────────────────────────────────────────────────────

/**
 * Returns all risks owned by the authenticated user.
 *
 * Server-side filters (all optional, supplied as query params):
 *   ?status=Open|In Progress|Mitigated
 *   ?severity_level=Low|Medium|High|Critical
 *   ?jncsf_capability=<one of the six JNCSF domains>
 *
 * Server-side sorting (optional):
 *   ?sort_by=created_at|quantitative_score|severity_level|title|status
 *   ?order=asc|desc   (default: desc)
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json(
        { error: "Authentication required. Provide a valid Bearer token." },
        { status: 401 }
      );
    }

    const { client } = auth;
    const { searchParams } = new URL(request.url);

    // ── Parse & validate filter params ──────────────────────────────────────

    const filterStatus = searchParams.get("status");
    const filterSeverity = searchParams.get("severity_level");
    const filterCapability = searchParams.get("jncsf_capability");

    if (filterStatus && !VALID_STATUSES.includes(filterStatus)) {
      return corsResponse(
        {
          error: "Invalid filter value",
          details: `status must be one of: ${VALID_STATUSES.join(", ")}.`,
        },
        400
      );
    }

    if (filterSeverity && !VALID_SEVERITY_LEVELS.includes(filterSeverity)) {
      return corsResponse(
        {
          error: "Invalid filter value",
          details: `severity_level must be one of: ${VALID_SEVERITY_LEVELS.join(", ")}.`,
        },
        400
      );
    }

    if (filterCapability && !VALID_CAPABILITIES.includes(filterCapability)) {
      return corsResponse(
        {
          error: "Invalid filter value",
          details: `jncsf_capability must be one of: ${VALID_CAPABILITIES.join(", ")}.`,
        },
        400
      );
    }

    // ── Parse & validate sort params ─────────────────────────────────────────

    const rawSortBy = searchParams.get("sort_by") || "created_at";
    const rawOrder = (searchParams.get("order") || "desc").toLowerCase();

    if (!SORTABLE_COLUMNS.includes(rawSortBy)) {
      return corsResponse(
        {
          error: "Invalid sort column",
          details: `sort_by must be one of: ${SORTABLE_COLUMNS.join(", ")}.`,
        },
        400
      );
    }

    if (!["asc", "desc"].includes(rawOrder)) {
      return corsResponse(
        { error: "Invalid sort order", details: "order must be 'asc' or 'desc'." },
        400
      );
    }

    // ── Build query ──────────────────────────────────────────────────────────

    let query = client.from("risks").select(RISK_SELECT_FIELDS);

    if (filterStatus) query = query.eq("status", filterStatus);
    if (filterSeverity) query = query.eq("severity_level", filterSeverity);
    if (filterCapability) query = query.eq("jncsf_capability", filterCapability);

    query = query.order(rawSortBy, { ascending: rawOrder === "asc" });

    const { data, error } = await query;

    if (error) {
      console.error("🔥 GET /api/risks — Supabase error:", error);
      throw error;
    }

    const sanitized = (data || []).map(sanitizeRisk);

    return new Response(JSON.stringify(sanitized), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/risks — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── POST /api/risks ──────────────────────────────────────────────────────────

/**
 * Creates a new risk record.
 *
 * Expected JSON body:
 * {
 *   "title":            string  (required, non-empty)
 *   "description":      string  (optional)
 *   "jncsf_capability": string  (required, must be a valid JNCSF domain)
 *   "likelihood":       integer (required, 1–5)
 *   "impact":           integer (required, 1–5)
 * }
 *
 * Business logic (server-side, never trusted from the client):
 *   - inherent_risk_score  = likelihood × impact
 *   - risk_level           = Low / Medium / High / Critical (score matrix)
 *   - status               = 'Open' (always)
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json(
        { error: "Authentication required. Provide a valid Bearer token." },
        { status: 401 }
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

    const { title, description, jncsf_capability, likelihood, impact } = body;

    // ── Validate inputs ──────────────────────────────────────────────────────

    const validationErrors = [];

    if (!title || typeof title !== "string" || title.trim().length === 0) {
      validationErrors.push("title is required and must be a non-empty string.");
    } else if (title.trim().length > 255) {
      validationErrors.push("title must not exceed 255 characters.");
    }

    if (!jncsf_capability || !VALID_CAPABILITIES.includes(jncsf_capability)) {
      validationErrors.push(
        `jncsf_capability is required and must be one of: ${VALID_CAPABILITIES.join(", ")}.`
      );
    }

    const parsedLikelihood = Number(likelihood);
    const parsedImpact = Number(impact);

    if (!Number.isInteger(parsedLikelihood) || parsedLikelihood < 1 || parsedLikelihood > 5) {
      validationErrors.push("likelihood is required and must be an integer between 1 and 5.");
    }

    if (!Number.isInteger(parsedImpact) || parsedImpact < 1 || parsedImpact > 5) {
      validationErrors.push("impact is required and must be an integer between 1 and 5.");
    }

    if (description !== undefined && typeof description !== "string") {
      validationErrors.push("description must be a string when provided.");
    }

    if (validationErrors.length > 0) {
      return corsResponse(
        { error: "Validation failed", details: validationErrors },
        400
      );
    }

    // ── Business logic: calculate score & risk level server-side ─────────────

    const { score: inherent_risk_score, severity_level: risk_level } =
      calculateRiskScore(parsedLikelihood, parsedImpact);

    // ── Insert record ────────────────────────────────────────────────────────

    const { data, error: insertError } = await client
      .from("risks")
      .insert({
        title: title.trim(),
        description: description?.trim() ?? null,
        jncsf_capability,
        likelihood: parsedLikelihood,
        impact: parsedImpact,
        quantitative_score: inherent_risk_score, // stored as inherent_risk_score
        severity_level: risk_level,
        status: "Open", // always default — never trust client-supplied status on create
      })
      .select(RISK_SELECT_FIELDS)
      .maybeSingle();

    if (insertError) {
      console.error("🔥 POST /api/risks — Supabase insert error:", insertError);
      return corsResponse(
        { error: "Failed to create risk", details: insertError.message },
        500
      );
    }

    if (!data) {
      return corsResponse(
        { error: "Failed to create risk", details: "No record returned after insert." },
        500
      );
    }

    // ── Audit log (non-blocking — failure must not break the response) ────────

    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "CREATED_RISK",
        table_name: "risks",
        record_id: data.id,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    return new Response(JSON.stringify(sanitizeRisk(data)), {
      status: 201,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 POST /api/risks — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/risks ───────────────────────────────────────────────────────

/**
 * Handles CORS preflight requests from the browser before POST.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
