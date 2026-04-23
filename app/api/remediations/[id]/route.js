import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

/**
 * PUT /api/remediations/[id]
 *
 * Updates the 'status' and 'notes' of an existing task.
 * RLS ensures users can only execute this if assigned to them.
 */
export async function PUT(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client, user } = auth;
    const { id } = params;

    if (!id) {
      return NextResponse.json({ error: "Task ID is required" }, { status: 400 });
    }

    const body = await request.json();
    const { status, notes } = body;

    const updates = {};
    if (status) {
       if (!["Open", "In Progress", "Resolved"].includes(status)) {
         return NextResponse.json({ error: "Status must be Open, In Progress, or Resolved." }, { status: 400 });
       }
       updates.status = status;
    }
    if (notes !== undefined) {
       updates.notes = notes;
    }

    const { data: updatedTask, error: updateError } = await client
      .from("remediation_tasks")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (updateError) {
      console.error("Task update error:", updateError);
      return NextResponse.json({ error: "Failed to update task", details: updateError.message }, { status: 500 });
    }

    // Audit log
    const ipAddress = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
      
    const { error: auditError } = await client
      .from("audit_logs")
      .insert({
        user_id: user.id,
        action: "UPDATED_REMEDIATION_TASK",
        table_name: "remediation_tasks",
        record_id: updatedTask.id,
        ip_address: ipAddress
      });

    if (auditError) console.error("Audit log failed:", auditError);

    return NextResponse.json(updatedTask, { status: 200 });
  } catch (err) {
    console.error("Error in PUT /api/remediations/[id]:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
