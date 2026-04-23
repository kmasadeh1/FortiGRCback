import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { getSupabase } from "@/lib/supabaseClient";

// Valid values for the select_principle_enum
const VALID_PRINCIPLES = [
  "Strategic",
  "Enterprise Driven",
  "Livable",
  "Economical",
  "Capability Based",
  "Trustable",
];

/**
 * GET /api/compliance
 *
 * Returns all compliance controls owned by the authenticated user,
 * joined with the linked risk's title.
 * Each row includes the full control data plus `risk_title`.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    // authenticateRequest validates the Bearer JWT via supabase.auth.getUser().
    // DO NOT use getSession() — it needs cookies and will always return null here.
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    // --- Query (RLS automatically scopes to the user's data) ----------------
    const { data, error } = await client
      .from("compliance_controls")
      .select("*, risks(title)")
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    // Flatten the nested `risks` object so the response has `risk_title` at the top level
    const flattened = data.map(({ risks, ...rest }) => ({
      ...rest,
      risk_title: risks?.title ?? null,
    }));

    return NextResponse.json(flattened, { status: 200 });
  } catch (err) {
    console.error("Unexpected error in GET /api/compliance:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

/**
 * POST /api/compliance
 *
 * Creates a new compliance control linked to an existing risk,
 * owned by the authenticated user.
 *
 * Request body (JSON):
 *   - risk_id           (string/UUID, required)
 *   - control_name      (string, required)
 *   - select_principle  (string, required — must match select_principle_enum)
 *   - is_compliant      (boolean, required)
 *
 * Requires: Authorization: Bearer <access_token>
 *
 * Returns the newly created compliance control row.
 */
export async function POST(request) {
  try {
    // --- Authenticate --------------------------------------------------------
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    // --- Parse body -----------------------------------------------------------
    const body = await request.json();
    const { risk_id, control_name, select_principle, is_compliant } = body;

    // --- Validate required fields --------------------------------------------
    const errors = [];

    if (!risk_id || typeof risk_id !== "string" || risk_id.trim().length === 0) {
      errors.push("risk_id is required and must be a valid UUID string.");
    }

    if (!control_name || typeof control_name !== "string" || control_name.trim().length === 0) {
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

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    // --- Insert into Supabase (user_id auto-set by DEFAULT auth.uid()) ------
    const { data, error } = await client
      .from("compliance_controls")
      .insert({
        risk_id: risk_id.trim(),
        control_name: control_name.trim(),
        select_principle,
        is_compliant,
      })
      .select()
      .maybeSingle();

    if (error || !data) {
      console.error("Supabase insert error:", error || "No data returned");

      // Surface a clear message when the referenced risk doesn't exist
      if (error?.code === "23503") {
        return NextResponse.json(
          { error: "Invalid risk_id", details: "The referenced risk does not exist." },
          { status: 400 }
        );
      }

      return NextResponse.json(
        { error: "Failed to create compliance control", details: error?.message || "Unknown error" },
        { status: 500 }
      );
    }

    return NextResponse.json(data, { status: 201 });
  } catch (err) {
    console.error("Unexpected error in POST /api/compliance:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/compliance
 *
 * Updates an existing compliance control by ID.
 * Accepts: id (required), and any of: control_name, select_principle, is_compliant
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function PUT(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    const body = await request.json();
    const { id, control_name, select_principle, is_compliant } = body;

    if (!id || typeof id !== "string") {
      return NextResponse.json({ error: "Validation failed", details: ["id is required to update a compliance control."] }, { status: 400 });
    }

    const updates = {};
    if (control_name !== undefined) {
      if (typeof control_name !== "string" || control_name.trim().length === 0) {
        return NextResponse.json({ error: "Validation failed", details: ["control_name must be a non-empty string."] }, { status: 400 });
      }
      updates.control_name = control_name.trim();
    }
    if (select_principle !== undefined) {
      if (!VALID_PRINCIPLES.includes(select_principle)) {
        return NextResponse.json({ error: "Validation failed", details: [`select_principle must be one of: ${VALID_PRINCIPLES.join(", ")}.`] }, { status: 400 });
      }
      updates.select_principle = select_principle;
    }
    if (is_compliant !== undefined) {
      if (typeof is_compliant !== "boolean") {
        return NextResponse.json({ error: "Validation failed", details: ["is_compliant must be a boolean."] }, { status: 400 });
      }
      updates.is_compliant = is_compliant;
    }

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "Validation failed", details: ["No valid fields provided to update."] }, { status: 400 });
    }

    const { data, error } = await client
      .from("compliance_controls")
      .update(updates)
      .eq("id", id)
      .select()
      .maybeSingle();

    if (error) {
      console.error("Supabase update error:", error);
      return NextResponse.json({ error: "Failed to update compliance control", details: error.message }, { status: 500 });
    }

    if (!data) {
      return NextResponse.json({ error: "Compliance control not found." }, { status: 404 });
    }

    return NextResponse.json(data, { status: 200 });
  } catch (err) {
    console.error("Unexpected error in PUT /api/compliance:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
