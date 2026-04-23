import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { checkRbac } from "@/app/api/utils/rbac";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

/**
 * GET /api/risks/exceptions
 *
 * Retrieves all risk exceptions.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: "No active session found" }, { status: 401 });
    }
    const { client } = auth;

    const { data, error } = await client
      .from("risk_exceptions")
      .select("*, risks(title)")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Supabase fetch error (risk_exceptions):", error);
      throw error;
    }

    return new Response(JSON.stringify(data), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * POST /api/risks/exceptions
 *
 * Request a new risk exception/waiver.
 * Requires at least 'Auditor' role.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Auditor");
    if (!hasPermission) {
      return NextResponse.json(
        { error: "Access Denied: You do not have the required permissions (Auditor or above)." },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { risk_id, justification, expiration_date } = body;

    const errors = [];
    if (!risk_id || typeof risk_id !== "string") errors.push("risk_id is required.");
    if (!justification || typeof justification !== "string") errors.push("justification is required.");
    if (!expiration_date) errors.push("expiration_date is required.");

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    const { data, error } = await client
      .from("risk_exceptions")
      .insert({
        risk_id,
        justification,
        expiration_date,
        status: "Pending",
        requested_by: auth.user.id
      })
      .select()
      .maybeSingle();

    if (error || !data) {
      console.error("Supabase insert error (risk_exceptions):", error || "No data returned");
      return NextResponse.json({ error: "Failed to create exception request", details: error?.message || "Unknown error" }, { status: 500 });
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    await client.from("audit_logs").insert({
      user_id: auth.user.id,
      action: "REQUESTED_EXCEPTION",
      table_name: "risk_exceptions",
      record_id: data.id,
      ip_address: ipAddress
    });

    return new Response(JSON.stringify(data), { status: 201, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * PUT /api/risks/exceptions
 *
 * Approve or Deny a risk exception.
 * Requires 'Admin' role.
 */
export async function PUT(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    const hasPermission = await checkRbac(client, auth.user.id, "Admin");
    if (!hasPermission) {
      return NextResponse.json(
        { error: "Access Denied: You do not have the required permissions (Admin only)." },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { exception_id, status } = body; // status: 'Approved' or 'Denied'

    if (!exception_id || !status || !["Approved", "Denied"].includes(status)) {
      return NextResponse.json({ error: "Validation failed: exception_id and valid status (Approved/Denied) are required." }, { status: 400 });
    }

    // Update risk_exception
    const { data: exceptionData, error: exceptionError } = await client
      .from("risk_exceptions")
      .update({ status })
      .eq("id", exception_id)
      .select()
      .maybeSingle();

    if (exceptionError || !exceptionData) {
      console.error("Supabase update error (risk_exceptions):", exceptionError || "Not found");
      return NextResponse.json({ error: "Failed to update exception status or not found", details: exceptionError?.message || "Not found" }, { status: 500 });
    }

    // If approved, update the risk to be excepted
    if (status === "Approved") {
      const { error: riskError } = await client
        .from("risks")
        .update({ is_excepted: true })
        .eq("id", exceptionData.risk_id);
        
      if (riskError) {
         console.error("Supabase update error (risks.is_excepted):", riskError);
         // Continuing, although we might want to fail the whole thing.
      }
    }

    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    await client.from("audit_logs").insert({
      user_id: auth.user.id,
      action: `REVIEWED_EXCEPTION_${status.toUpperCase()}`,
      table_name: "risk_exceptions",
      record_id: exception_id,
      ip_address: ipAddress
    });

    return new Response(JSON.stringify(exceptionData), { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/risks/exceptions
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
