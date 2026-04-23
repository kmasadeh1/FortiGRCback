import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight } from "@/lib/cors";

/**
 * GET /api/assessments
 *
 * Fetches the first 'Pending' assessment for the current user,
 * along with all related questions from `assessment_questions`.
 *
 * Returns:
 * {
 *   assessment: {
 *     id, title, description, status,
 *     questions: [ { id, text, risk_impact_title, risk_severity, jncsf_capability } ]
 *   }
 * }
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client } = auth;

    // Fetch primary pending assessment with its questions joined
    const { data: assessment, error: assessmentError } = await client
      .from("assessments")
      .select(`
        id,
        title,
        description,
        status,
        assessment_questions (
          id,
          text,
          risk_impact_title,
          risk_severity,
          jncsf_capability
        )
      `)
      .eq("status", "Pending")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    if (assessmentError) {
      console.error("🔥 Failed to fetch assessment:", assessmentError);
      return corsResponse({ error: "Failed to fetch assessment.", details: assessmentError.message }, 500);
    }

    if (!assessment) {
      return NextResponse.json({ assessment: null, message: "No pending assessments found." }, { status: 200 });
    }

    // Normalize nested questions key from Supabase join syntax
    const response = {
      assessment: {
        id: assessment.id,
        title: assessment.title,
        description: assessment.description,
        status: assessment.status,
        questions: assessment.assessment_questions || [],
      }
    };

    return NextResponse.json(response, { status: 200 });
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

/**
 * OPTIONS /api/assessments
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
