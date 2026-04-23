import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { checkRbac } from "@/app/api/utils/rbac";

const VALID_PRINCIPLES = [
  "Strategic",
  "Enterprise Driven",
  "Livable",
  "Economical",
  "Capability Based",
  "Trustable",
];

/**
 * PUT /api/controls/[id]
 *
 * Updates an existing compliance control by ID.
 * Accepts: control_name, risk_id, select_principle, is_compliant, jncf_mapping_id
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

    const { id } = await context.params; // Next.js 15: params is a Promise

    if (!id) {
      return corsResponse({ error: "Missing control ID in URL" }, 400);
    }

    const body = await request.json();
    const { control_name, risk_id, select_principle, is_compliant, jncf_mapping_id } = body;

    const updates = {};
    const errors = [];

    if (control_name !== undefined) {
      if (typeof control_name !== "string" || control_name.trim().length === 0) {
        errors.push("control_name must be a non-empty string.");
      } else {
        updates.control_name = control_name.trim();
      }
    }

    if (risk_id !== undefined) {
      if (typeof risk_id !== "string" || risk_id.trim().length === 0) {
        errors.push("risk_id must be a valid UUID string.");
      } else {
        updates.risk_id = risk_id.trim();
      }
    }

    if (select_principle !== undefined) {
      if (!VALID_PRINCIPLES.includes(select_principle)) {
        errors.push(`select_principle must be one of: ${VALID_PRINCIPLES.join(", ")}.`);
      } else {
        updates.select_principle = select_principle;
      }
    }

    if (is_compliant !== undefined) {
      if (typeof is_compliant !== "boolean") {
        errors.push("is_compliant must be a boolean.");
      } else {
        updates.is_compliant = is_compliant;
      }
    }

    if (jncf_mapping_id !== undefined) {
      if (jncf_mapping_id !== null && (typeof jncf_mapping_id !== "string" || jncf_mapping_id.trim().length === 0)) {
        errors.push("jncf_mapping_id must be a valid UUID string or null.");
      } else {
        updates.jncf_mapping_id = jncf_mapping_id ? jncf_mapping_id.trim() : null;
      }
    }

    if (errors.length > 0) {
      return corsResponse({ error: "Validation failed", details: errors }, 400);
    }

    if (Object.keys(updates).length === 0) {
      return corsResponse({ error: "No valid fields provided to update." }, 400);
    }

    const { data, error } = await client
      .from("compliance_controls")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      if (error.code === "23503") {
        if (error.message.includes("jncf_mapping_id")) {
          return corsResponse({ error: "Invalid jncf_mapping_id: JNCF control does not exist." }, 400);
        }
        return corsResponse({ error: "Invalid risk_id: Risk does not exist." }, 400);
      }
      return corsResponse({ success: false, error: error.message }, 500);
    }

    // Audit log (non-blocking)
    const ipAddress =
      request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      "unknown";

    client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "UPDATED_CONTROL",
        table_name: "compliance_controls",
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
 * DELETE /api/controls/[id]
 *
 * Permanently deletes a compliance control by ID.
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

    const { id } = await context.params; // Next.js 15: params is a Promise

    if (!id) {
      return corsResponse({ error: "Missing control ID in URL" }, 400);
    }

    const { error } = await client
      .from("compliance_controls")
      .delete()
      .eq("id", id);

    if (error) {
      console.error("🔥 BACKEND CRASH ERROR:", error);
      return corsResponse({ success: false, error: error.message }, 500);
    }

    // Audit log (non-blocking)
    const ipAddress =
      request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      "unknown";

    client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "DELETED_CONTROL",
        table_name: "compliance_controls",
        record_id: id,
        ip_address: ipAddress,
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log failed:", auditErr);
      });

    return new Response(
      JSON.stringify({ success: true, message: `Control ${id} deleted successfully.` }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/controls/[id]
 * Handles CORS preflight for PUT and DELETE requests.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
