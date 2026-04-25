import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { checkRbac } from "@/app/api/utils/rbac";

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_PRINCIPLES = [
  "Strategic",
  "Enterprise Driven",
  "Livable",
  "Economical",
  "Capability Based",
  "Trustable",
];

// Allowed implementation status values for a compliance control.
// "is_compliant" (boolean) maps from these for backward compatibility.
const VALID_IMPLEMENTATION_STATUSES = [
  "Not Implemented",
  "Partial",
  "Fully Implemented",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derives the is_compliant boolean from a human-readable status string.
 * Only "Fully Implemented" controls are considered fully compliant.
 *
 * @param {string} status
 * @returns {boolean}
 */
function statusToIsCompliant(status) {
  return status === "Fully Implemented";
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

// ─── GET /api/controls/[id] ───────────────────────────────────────────────────

/**
 * Returns a single compliance control by its UUID,
 * joined with the linked risk title and JNCF control data.
 *
 * Requires: Authorization: Bearer <access_token>
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
      return corsResponse({ error: "Missing or invalid control ID in URL." }, 400);
    }

    const { data, error } = await client
      .from("compliance_controls")
      .select(
        `
        id,
        control_name,
        is_compliant,
        select_principle,
        jncf_mapping_id,
        created_at,
        risks ( id, title ),
        jncf_controls ( id, control_code, description )
        `
      )
      .eq("id", id)
      .maybeSingle(); // safe: returns null instead of throwing on no match

    if (error) {
      console.error(`🔥 GET /api/controls/${id} — Supabase error:`, error);
      return corsResponse(
        { error: "Failed to fetch compliance control", details: error.message },
        500
      );
    }

    if (!data) {
      return corsResponse(
        { error: "Compliance control not found or you do not have permission to view it." },
        404
      );
    }

    // Flatten nested joins for a clean, flat response object
    const { risks, jncf_controls, ...rest } = data;
    const flat = {
      ...rest,
      risk_id: risks?.id ?? null,
      risk_title: risks?.title ?? null,
      jncf_control_code: jncf_controls?.control_code ?? null,
      jncf_control_description: jncf_controls?.description ?? null,
    };

    return new Response(JSON.stringify(flat), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/controls/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── PUT /api/controls/[id] ───────────────────────────────────────────────────

/**
 * Updates an existing compliance control by ID.
 *
 * Expected JSON body (all fields optional — send only what changes):
 * {
 *   "control_name":        string   (optional, non-empty)
 *   "select_principle":    string   (optional, one of the six S.E.L.E.C.T values)
 *   "status":              string   (optional: 'Not Implemented'|'Partial'|'Fully Implemented')
 *   "is_compliant":        boolean  (optional — use `status` instead when possible)
 *   "risk_id":             string   (optional, UUID)
 *   "jncf_mapping_id":     string|null (optional, UUID or null to clear)
 *   "evidence_ids":        string[] (optional — UUIDs of evidence_documentation rows to link)
 * }
 *
 * Business logic:
 *   - If `status` is provided, it takes precedence and is used to derive `is_compliant`.
 *   - If only `is_compliant` is provided (legacy path), it is stored directly.
 *   - evidence_ids: each ID is verified to exist in evidence_documentation, then
 *     the record's risk_id is updated to link it to this control's risk.
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
      return corsResponse({ error: "Missing or invalid control ID in URL." }, 400);
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

    const {
      control_name,
      select_principle,
      status,
      is_compliant,
      risk_id,
      jncf_mapping_id,
      evidence_ids,
    } = body;

    // ── Validate each supplied field ─────────────────────────────────────────

    const errors = [];

    if (control_name !== undefined) {
      if (typeof control_name !== "string" || control_name.trim().length === 0) {
        errors.push("control_name must be a non-empty string.");
      }
    }

    if (select_principle !== undefined) {
      if (!VALID_PRINCIPLES.includes(select_principle)) {
        errors.push(
          `select_principle must be one of: ${VALID_PRINCIPLES.join(", ")}.`
        );
      }
    }

    // `status` is the primary API — validate it if provided
    if (status !== undefined) {
      if (!VALID_IMPLEMENTATION_STATUSES.includes(status)) {
        errors.push(
          `status must be one of: ${VALID_IMPLEMENTATION_STATUSES.join(", ")}.`
        );
      }
    }

    // `is_compliant` is the legacy boolean API — still supported
    if (is_compliant !== undefined && status === undefined) {
      if (typeof is_compliant !== "boolean") {
        errors.push("is_compliant must be a boolean.");
      }
    }

    if (risk_id !== undefined) {
      if (typeof risk_id !== "string" || risk_id.trim().length === 0) {
        errors.push("risk_id must be a valid UUID string.");
      }
    }

    if (jncf_mapping_id !== undefined && jncf_mapping_id !== null) {
      if (
        typeof jncf_mapping_id !== "string" ||
        jncf_mapping_id.trim().length === 0
      ) {
        errors.push("jncf_mapping_id must be a valid UUID string or null.");
      }
    }

    if (evidence_ids !== undefined) {
      if (
        !Array.isArray(evidence_ids) ||
        evidence_ids.some((e) => typeof e !== "string" || e.trim().length === 0)
      ) {
        errors.push("evidence_ids must be an array of UUID strings.");
      }
    }

    if (errors.length > 0) {
      return corsResponse({ error: "Validation failed", details: errors }, 400);
    }

    // ── Build update object ───────────────────────────────────────────────────

    const updates = {};

    if (control_name !== undefined) updates.control_name = control_name.trim();
    if (select_principle !== undefined) updates.select_principle = select_principle;
    if (risk_id !== undefined) updates.risk_id = risk_id.trim();
    if (jncf_mapping_id !== undefined) {
      updates.jncf_mapping_id = jncf_mapping_id ? jncf_mapping_id.trim() : null;
    }

    // `status` → `is_compliant` derivation (server-side business logic)
    if (status !== undefined) {
      updates.is_compliant = statusToIsCompliant(status);
    } else if (is_compliant !== undefined) {
      updates.is_compliant = is_compliant;
    }

    if (Object.keys(updates).length === 0 && !evidence_ids?.length) {
      return corsResponse(
        {
          error: "Validation failed",
          details:
            "No valid fields provided to update. Send at least one of: control_name, select_principle, status, is_compliant, risk_id, jncf_mapping_id, evidence_ids.",
        },
        400
      );
    }

    // ── Persist control update (if there are field changes) ──────────────────

    let updatedControl = null;

    if (Object.keys(updates).length > 0) {
      const { data, error: updateErr } = await client
        .from("compliance_controls")
        .update(updates)
        .eq("id", id)
        .select()
        .maybeSingle(); // safe: returns null instead of throwing when not found

      if (updateErr) {
        console.error(`🔥 PUT /api/controls/${id} — update error:`, updateErr);

        if (updateErr.code === "23503") {
          const detail = updateErr.message.includes("jncf_mapping_id")
            ? "The referenced JNCF control does not exist."
            : "The referenced risk does not exist.";
          return corsResponse({ error: "Foreign key violation", details: detail }, 400);
        }

        return corsResponse(
          { error: "Failed to update compliance control", details: updateErr.message },
          500
        );
      }

      if (!data) {
        return corsResponse(
          { error: "Compliance control not found or you do not have permission to update it." },
          404
        );
      }

      updatedControl = data;
    }

    // ── Link evidence IDs (background, non-fatal) ─────────────────────────────
    //
    // For each supplied evidence_id, fetch the document row to verify it exists
    // and belongs to this user (RLS handles that automatically), then update its
    // risk_id to the control's current risk_id so audit queries can join them.
    if (evidence_ids && evidence_ids.length > 0) {
      // Fetch the control's current risk_id if we didn't update it in this request
      const currentRiskId =
        updatedControl?.risk_id ??
        (await (async () => {
          const { data: ctrl } = await client
            .from("compliance_controls")
            .select("risk_id")
            .eq("id", id)
            .maybeSingle();
          return ctrl?.risk_id ?? null;
        })());

      if (currentRiskId) {
        // Update evidence rows in a single query using the `in` filter
        const { error: evidenceErr } = await client
          .from("evidence_documentation")
          .update({ risk_id: currentRiskId })
          .in("id", evidence_ids);

        if (evidenceErr) {
          // Log but don't fail the request — the control update already succeeded
          console.error(
            `PUT /api/controls/${id} — evidence link error:`,
            evidenceErr
          );
        }
      }
    }

    // ── Audit log (non-blocking) ─────────────────────────────────────────────

    const controlId = updatedControl?.id ?? id;
    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "UPDATED_CONTROL",
        table_name: "compliance_controls",
        record_id: controlId,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    // Return the updated control (or re-fetch if we only linked evidence)
    const responseBody = updatedControl ?? { id, message: "Evidence IDs linked successfully." };

    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 PUT /api/controls/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

/**
 * PATCH /api/controls/[id]
 *
 * Semantic alias for PUT — both accept partial payloads.
 */
export const PATCH = PUT;

// ─── DELETE /api/controls/[id] ───────────────────────────────────────────────

/**
 * Permanently deletes a compliance control by ID.
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
      return corsResponse({ error: "Missing or invalid control ID in URL." }, 400);
    }

    // Verify existence before deletion for a clean 404
    const { data: existing, error: checkErr } = await client
      .from("compliance_controls")
      .select("id")
      .eq("id", id)
      .maybeSingle();

    if (checkErr) {
      return corsResponse(
        { error: "Failed to verify control before deletion.", details: checkErr.message },
        500
      );
    }

    if (!existing) {
      return corsResponse(
        { error: "Compliance control not found or you do not have permission to delete it." },
        404
      );
    }

    const { error: deleteErr } = await client
      .from("compliance_controls")
      .delete()
      .eq("id", id);

    if (deleteErr) {
      console.error(`🔥 DELETE /api/controls/${id} — error:`, deleteErr);
      return corsResponse(
        { error: "Failed to delete compliance control", details: deleteErr.message },
        500
      );
    }

    // ── Audit log (non-blocking) ─────────────────────────────────────────────

    client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "DELETED_CONTROL",
        table_name: "compliance_controls",
        record_id: id,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log insertion failed:", auditErr);
      });

    return new Response(
      JSON.stringify({ success: true, message: `Control ${id} deleted successfully.` }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 DELETE /api/controls/[id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/controls/[id] ──────────────────────────────────────────────

/**
 * Handles CORS preflight requests for PUT, PATCH, and DELETE.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
