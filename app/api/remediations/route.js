import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

/**
 * POST /api/remediations
 *
 * Creates a new remediation task linked to a risk.
 * Validates risk existence and inserts to audit_logs securely.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client, user } = auth;

    const body = await request.json();
    const { risk_id, assigned_to, due_date, status, notes } = body;

    const errors = [];

    if (!risk_id || typeof risk_id !== "string") {
      errors.push("risk_id is required.");
    }
    if (!assigned_to || typeof assigned_to !== "string") {
      errors.push("assigned_to is required.");
    }
    
    // Status validation
    if (status && !["Open", "In Progress", "Resolved"].includes(status)) {
       errors.push("Status must be Open, In Progress, or Resolved.");
    }

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    // Insert task
    const { data: taskData, error: insertError } = await client
      .from("remediation_tasks")
      .insert({
        risk_id: risk_id.trim(),
        assigned_to: assigned_to.trim(),
        due_date: due_date || null,
        status: status || "Open",
        notes: notes || ""
      })
      .select()
      .single();

    if (insertError) {
      console.error("Task insert error:", insertError);
      if (insertError.code === "23503") {
         return NextResponse.json({ error: "Invalid foreign key constraint, please ensure risk_id and assigned_to exist." }, { status: 400 });
      }
      return NextResponse.json({ error: "Failed to create task", details: insertError.message }, { status: 500 });
    }

    // Audit log
    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "CREATED_REMEDIATION_TASK",
        table_name: "remediation_tasks",
        record_id: taskData.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log failed:", auditError);

    return NextResponse.json(taskData, { status: 201 });
  } catch (err) {
    console.error("Error in POST /api/remediations:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
