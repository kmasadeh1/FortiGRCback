import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { authenticateRequest } from "@/lib/authGuard";

// ─── GET /api/assessments ─────────────────────────────────────────────────────

/**
 * Returns all available (Pending) assessments for the authenticated user,
 * each with its full question list pre-loaded so the frontend can render
 * without a second fetch.
 *
 * Response shape:
 * {
 *   assessments: [
 *     {
 *       id:             string (UUID),
 *       title:          string,
 *       description:    string | null,
 *       status:         "Pending",
 *       question_count: number,
 *       questions: [
 *         {
 *           id:                string,
 *           text:              string,
 *           risk_impact_title: string,
 *           risk_severity:     string,
 *           jncsf_capability:  string
 *         }
 *       ]
 *     }
 *   ],
 *   total: number
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

    // Fetch all pending assessments with questions in one query.
    // RLS on the assessments table scopes this to records the user can see.
    const { data: assessments, error } = await client
      .from("assessments")
      .select(
        `
        id,
        title,
        description,
        status,
        created_at,
        assessment_questions (
          id,
          text,
          risk_impact_title,
          risk_severity,
          jncsf_capability
        )
      `
      )
      .eq("status", "Pending")
      .order("created_at", { ascending: true });

    if (error) {
      console.error("🔥 GET /api/assessments — Supabase error:", error);
      return corsResponse(
        { error: "Failed to fetch assessments", details: error.message },
        500
      );
    }

    // Normalize the nested key from Supabase's join syntax and add question_count
    const normalized = (assessments || []).map((a) => ({
      id: a.id,
      title: a.title,
      description: a.description ?? null,
      status: a.status,
      created_at: a.created_at,
      question_count: (a.assessment_questions || []).length,
      questions: a.assessment_questions || [],
    }));

    return new Response(
      JSON.stringify({ assessments: normalized, total: normalized.length }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 GET /api/assessments — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/assessments ─────────────────────────────────────────────────

export function OPTIONS() {
  return handleCORSPreflight();
}
