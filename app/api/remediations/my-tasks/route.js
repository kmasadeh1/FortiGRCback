import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

/**
 * GET /api/remediations/my-tasks
 *
 * Fetches all remediation tasks explicitly assigned to the currently
 * authenticated user. Used to populate the specific user dashboard.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client, user } = auth;

    // The user's JWT ID dictates what tasks they are inherently assigned.
    // RLS also physically blocks access to tasks not assigned to them unless they are admins.
    // However, explicitly filtering by `assigned_to` ensures we strictly return their personal list.
    const { data: tasks, error: fetchError } = await client
      .from("remediation_tasks")
      .select(`
        id,
        due_date,
        status,
        notes,
        created_at,
        risks (
          title,
          severity_level
        )
      `)
      .eq("assigned_to", user.id)
      .order("created_at", { ascending: false });

    if (fetchError) {
      console.error("Task fetch error:", fetchError);
      return NextResponse.json({ error: "Failed to fetch tasks", details: fetchError.message }, { status: 500 });
    }

    return NextResponse.json(tasks, { status: 200 });
  } catch (err) {
    console.error("Error in GET /api/remediations/my-tasks:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
