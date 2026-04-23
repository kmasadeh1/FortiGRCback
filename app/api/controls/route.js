import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { getSupabase } from "@/lib/supabaseClient";
import { checkRbac } from "@/app/api/utils/rbac";

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
 * POST /api/controls
 *
 * Creates a new compliance control linked to an existing risk,
 * owned by the authenticated user, and logs the action to audit_logs.
 * Now optionally accepts jncf_mapping_id to map into the national framework.
 */
export async function POST(request) {
  try {
    // authenticateRequest validates the Bearer JWT via supabase.auth.getUser().
    // DO NOT use getSession() — it needs cookies and will always return null here.
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    const body = await request.json();
    const { risk_id, control_name, select_principle, is_compliant, jncf_mapping_id } = body;

    const errors = [];

    if (!risk_id || typeof risk_id !== "string" || risk_id.trim().length === 0) {
      errors.push("risk_id is required and must be a valid UUID string.");
    }

    if (!control_name || typeof control_name !== "string" || control_name.trim().length === 0) {
      errors.push("control_name is required and must be a non-empty string.");
    }

    if (!select_principle || !VALID_PRINCIPLES.includes(select_principle)) {
      errors.push(`select_principle is required and must be one of: ${VALID_PRINCIPLES.join(", ")}.`);
    }

    if (typeof is_compliant !== "boolean") {
      errors.push("is_compliant is required and must be a boolean.");
    }

    if (jncf_mapping_id !== undefined && jncf_mapping_id !== null) {
      if (typeof jncf_mapping_id !== "string" || jncf_mapping_id.trim().length === 0) {
        errors.push("jncf_mapping_id must be a valid UUID string if provided.");
      }
    }

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    const { data, error } = await client
      .from("compliance_controls")
      .insert({
        risk_id: risk_id.trim(),
        control_name: control_name.trim(),
        select_principle,
        is_compliant,
        jncf_mapping_id: jncf_mapping_id ? jncf_mapping_id.trim() : null
      })
      .select()
      .single();

    if (error) {
      console.error("Supabase insert error:", error);
      if (error.code === "23503") {
        if (error.message.includes("jncf_mapping_id")) {
           return NextResponse.json({ error: "Invalid jncf_mapping_id", details: "The referenced JNCF control does not exist." }, { status: 400 });
        }
        return NextResponse.json({ error: "Invalid risk_id", details: "The referenced risk does not exist." }, { status: 400 });
      }
      return NextResponse.json({ error: "Failed to create compliance control", details: error.message }, { status: 500 });
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "CREATED_CONTROL",
        table_name: "compliance_controls",
        record_id: data.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log insertion failed:", auditError);

    return NextResponse.json(data, { status: 201 });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return new Response(JSON.stringify({ success: false, error: error.message || "Unknown error" }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

/**
 * PUT /api/controls
 *
 * Updates an existing compliance control.
 */
export async function PUT(request) {
  try {
    // authenticateRequest validates the Bearer JWT via supabase.auth.getUser().
    // DO NOT use getSession() — it needs cookies and will always return null here.
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Risk Manager");
    if (!hasPermission) {
      return NextResponse.json(
        { error: "Access Denied: You do not have the required permissions (Admin/Risk Manager)." },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { id, control_name, select_principle, is_compliant, jncf_mapping_id } = body;

    if (!id || typeof id !== "string") {
      return NextResponse.json({ error: "Validation failed", details: ["id is required to update a control."] }, { status: 400 });
    }

    const updates = {};
    if (control_name !== undefined) updates.control_name = control_name.trim();
    if (select_principle !== undefined) {
      if (!VALID_PRINCIPLES.includes(select_principle)) {
         return NextResponse.json({ error: "Validation failed", details: [`select_principle must be one of: ${VALID_PRINCIPLES.join(", ")}.`] }, { status: 400 });
      }
      updates.select_principle = select_principle;
    }
    if (is_compliant !== undefined) {
      if (typeof is_compliant !== "boolean") return NextResponse.json({ error: "Validation failed", details: ["is_compliant must be a boolean."] }, { status: 400 });
      updates.is_compliant = is_compliant;
    }
    if (jncf_mapping_id !== undefined) {
      if (jncf_mapping_id !== null && (typeof jncf_mapping_id !== "string" || jncf_mapping_id.trim().length === 0)) {
         return NextResponse.json({ error: "Validation failed", details: ["jncf_mapping_id must be a valid string or null."] }, { status: 400 });
      }
      updates.jncf_mapping_id = jncf_mapping_id ? jncf_mapping_id.trim() : null;
    }

    const { data, error } = await client
      .from("compliance_controls")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      throw error;
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "UPDATED_CONTROL",
        table_name: "compliance_controls",
        record_id: data.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log insertion failed:", auditError);

    return NextResponse.json(data, { status: 200 });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return new Response(JSON.stringify({ success: false, error: error.message || "Unknown error" }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}
