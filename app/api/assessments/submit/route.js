import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { calculateRiskScore } from "@/lib/riskScoring";

/**
 * Maps a string severity label to likelihood & impact values.
 */
function mapSeverityToScores(severity) {
  const sev = (severity || "").toLowerCase();
  if (sev.includes("critical")) return { likelihood: 5, impact: 5 };
  if (sev.includes("high"))     return { likelihood: 4, impact: 4 };
  if (sev.includes("medium"))   return { likelihood: 3, impact: 3 };
  return { likelihood: 2, impact: 2 }; // Default: Low
}

/**
 * POST /api/assessments/submit
 *
 * Submits an assessment. For every "No" (false) answer, queries the
 * `assessment_questions` table for the question's `risk_impact_title`
 * and `risk_severity`, then inserts a new risk into the `risks` table.
 *
 * Request payload:
 * {
 *   assessmentId: string,     // UUID of the assessment
 *   title: string,            // Assessment title (for description context)
 *   answers: [
 *     {
 *       question_id: string,  // UUID — used to fetch question metadata
 *       value: boolean | 'No' // false or 'No' means failed
 *     }
 *   ]
 * }
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client } = auth;

    const body = await request.json();
    const { assessmentId, title, answers } = body;

    if (!Array.isArray(answers) || answers.length === 0) {
      return NextResponse.json(
        { error: "Validation failed: 'answers' must be a non-empty array." },
        { status: 400 }
      );
    }

    if (!title || typeof title !== "string") {
      return NextResponse.json(
        { error: "Validation failed: 'title' is required." },
        { status: 400 }
      );
    }

    // Filter to only failed answers (value is false, 'false', 'No', or 'no')
    const failedAnswers = answers.filter(
      (a) => a.value === false || a.value === "false" || a.value === "No" || a.value === "no"
    );

    const insertedRisks = [];

    // Process each failed answer individually so we can query the question metadata
    for (const answer of failedAnswers) {
      // 1. Fetch question metadata from assessment_questions
      let risk_impact_title = "Failed Assessment Control";
      let risk_severity = "Medium";

      if (answer.question_id) {
        const { data: question, error: questionError } = await client
          .from("assessment_questions")
          .select("risk_impact_title, risk_severity")
          .eq("id", answer.question_id)
          .maybeSingle();

        if (questionError) {
          console.error("SUPABASE ERROR: Failed to fetch question metadata:", questionError);
        } else if (question) {
          if (question.risk_impact_title) risk_impact_title = question.risk_impact_title;
          if (question.risk_severity)     risk_severity = question.risk_severity;
        }
      }

      // 2. Map severity to internal risk matrix values
      const { likelihood, impact } = mapSeverityToScores(risk_severity);
      const { score, severity_level } = calculateRiskScore(likelihood, impact);

      // 3. Insert the new risk
      const { data: newRisk, error: insertError } = await client
        .from("risks")
        .insert({
          title: risk_impact_title,
          jncsf_capability: "Fundamental Capabilities",
          likelihood,
          impact,
          quantitative_score: score,
          severity_level,
          status: "Open",
          user_id: auth.user.id,
        })
        .select()
        .single();

      if (insertError) {
        console.error("SUPABASE ERROR:", insertError);
        return NextResponse.json(
          { error: insertError.message },
          { status: 400 }
        );
      }

      insertedRisks.push(newRisk);
    }

    // 4. Update assessment status to 'Completed'
    if (assessmentId) {
      const { error: assessmentUpdateError } = await client
        .from("assessments")
        .update({ status: "Completed" })
        .eq("id", assessmentId);

      if (assessmentUpdateError) {
        console.error("SUPABASE ERROR: Failed to update assessment status:", assessmentUpdateError);
        // Non-fatal — continue so the user sees their generated risks
      }
    }

    // 5. Write audit log (non-blocking)
    const ipAddress =
      request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      "unknown";

    client
      .from("audit_logs")
      .insert({
        user_id: auth.user.id,
        action: "SUBMITTED_ASSESSMENT",
        table_name: "assessments",
        record_id: assessmentId || null,
        ip_address: ipAddress,
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log failed:", auditErr);
      });

    return new Response(
      JSON.stringify({
        success: true,
        message: `Assessment processed. Created ${insertedRisks.length} new risks based on your answers.`,
        created_risks: insertedRisks,
      }),
      { status: 201, headers: CORS_HEADERS }
    );
  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return NextResponse.json(
      { error: error.message || "Unknown internal error" },
      { status: 500 }
    );
  }
}

/**
 * OPTIONS /api/assessments/submit
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
