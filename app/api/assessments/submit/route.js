import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { authenticateRequest } from "@/lib/authGuard";
import { calculateRiskScore } from "@/lib/riskScoring";

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Minimum percentage of correct answers required to pass an assessment.
 * Any score below this threshold is graded as "Fail".
 */
const PASS_THRESHOLD = 70;

/**
 * The JNCSF capability assigned to auto-generated risks when a question
 * does not specify one. Defaults to the most general domain.
 */
const DEFAULT_JNCSF_CAPABILITY = "Fundamental Capabilities";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Returns true when an answer value represents a failing (No/false) response.
 *
 * @param {boolean | string} value
 * @returns {boolean}
 */
function isFailed(value) {
  return (
    value === false ||
    value === "false" ||
    value === "No" ||
    value === "no"
  );
}

/**
 * Maps a string severity label to likelihood & impact integer values
 * used by the risk scoring matrix.
 *
 * @param {string | null | undefined} severity
 * @returns {{ likelihood: number, impact: number }}
 */
function severityToScores(severity) {
  const s = (severity || "").toLowerCase();
  if (s.includes("critical")) return { likelihood: 5, impact: 5 };
  if (s.includes("high"))     return { likelihood: 4, impact: 4 };
  if (s.includes("medium"))   return { likelihood: 3, impact: 3 };
  return { likelihood: 2, impact: 2 }; // Low / default
}

/**
 * Derives the correct JNCSF capability domain to use.
 * Falls back to the default when the value from the question is missing or
 * not one of the six valid enum values.
 *
 * @param {string | null | undefined} capability
 * @returns {string}
 */
const VALID_CAPABILITIES = new Set([
  "Architecture & Portfolio",
  "Development",
  "Delivery",
  "Operations",
  "Fundamental Capabilities",
  "National Cyber Responsibility",
]);

function resolveCapability(capability) {
  return VALID_CAPABILITIES.has(capability) ? capability : DEFAULT_JNCSF_CAPABILITY;
}

/**
 * Extracts the client IP from standard proxy headers.
 *
 * @param {Request} request
 * @returns {string}
 */
function getClientIp(request) {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    request.headers.get("x-real-ip")?.trim() ||
    "unknown"
  );
}

// ─── POST /api/assessments/submit ─────────────────────────────────────────────

/**
 * Grades a submitted assessment and performs all downstream actions server-side.
 *
 * Expected JSON body:
 * {
 *   "assessmentId": string   (optional UUID — the assessment being completed)
 *   "title":        string   (required — name of the assessment for history record)
 *   "answers": [
 *     {
 *       "question_id": string,          (UUID of the assessment_questions row)
 *       "value":       boolean | string  (true/"Yes" = pass, false/"No" = fail)
 *     }
 *   ]
 * }
 *
 * Business logic (all server-side):
 *  1. Validate inputs.
 *  2. Grade: score = (passed_count / total_count) × 100.
 *  3. Determine pass/fail status against the PASS_THRESHOLD (70%).
 *  4. For every failed answer:
 *       a. Fetch question metadata (risk_impact_title, risk_severity, jncsf_capability).
 *       b. Map severity → likelihood + impact.
 *       c. Calculate inherent_risk_score and risk_level via calculateRiskScore().
 *       d. Insert a new risk tagged with source = "Assessment".
 *       e. Attempt to insert a remediation task assigned to the submitting user.
 *  5. Save a record to assessment_history (title, score string, completed_by).
 *  6. Mark the source assessment as "Completed" (non-fatal if assessmentId absent).
 *  7. Write an audit log entry (non-blocking, non-fatal).
 *  8. Return the consolidated result payload.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    // ── Authenticate ──────────────────────────────────────────────────────────

    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client, user } = auth;

    // ── Parse body ────────────────────────────────────────────────────────────

    let body;
    try {
      body = await request.json();
    } catch {
      return corsResponse(
        { error: "Invalid request body", details: "Request body must be valid JSON." },
        400
      );
    }

    const { assessmentId, title, answers } = body;

    // ── Validate inputs ───────────────────────────────────────────────────────

    const errors = [];

    if (!title || typeof title !== "string" || title.trim().length === 0) {
      errors.push("title is required and must be a non-empty string.");
    }

    if (!Array.isArray(answers) || answers.length === 0) {
      errors.push("answers must be a non-empty array of { question_id, value } objects.");
    } else {
      const malformed = answers.filter(
        (a) => !a || typeof a.question_id !== "string" || a.question_id.trim().length === 0
      );
      if (malformed.length > 0) {
        errors.push("Each answer must have a valid question_id string.");
      }
    }

    if (errors.length > 0) {
      return corsResponse({ error: "Validation failed", details: errors }, 400);
    }

    // ── Step 1: Grade the assessment server-side ──────────────────────────────

    const totalQuestions = answers.length;
    const failedAnswers  = answers.filter((a) => isFailed(a.value));
    const passedCount    = totalQuestions - failedAnswers.length;

    const rawScore = (passedCount / totalQuestions) * 100;
    const score    = Math.round(rawScore * 10) / 10; // one decimal place
    const passed   = score >= PASS_THRESHOLD;
    const status   = passed ? "Pass" : "Fail";
    const scoreStr = `${score}%`;

    // ── Step 2: Process each failed answer → create risks + remediation ───────

    const createdRisks             = [];
    const createdRemediationTasks  = [];

    for (const answer of failedAnswers) {
      // 2a. Fetch question metadata to drive risk generation
      let riskTitle    = "Failed Assessment Control";
      let riskSeverity = "Medium";
      let capability   = DEFAULT_JNCSF_CAPABILITY;

      if (answer.question_id) {
        const { data: question, error: qErr } = await client
          .from("assessment_questions")
          .select("risk_impact_title, risk_severity, jncsf_capability")
          .eq("id", answer.question_id.trim())
          .maybeSingle();

        if (qErr) {
          console.error(
            `Submit: failed to fetch question ${answer.question_id}:`,
            qErr
          );
        } else if (question) {
          if (question.risk_impact_title) riskTitle    = question.risk_impact_title;
          if (question.risk_severity)     riskSeverity = question.risk_severity;
          if (question.jncsf_capability)  capability   = question.jncsf_capability;
        }
      }

      // 2b–c. Map severity → scores (server-side, never trusted from client)
      const { likelihood, impact } = severityToScores(riskSeverity);
      const { score: riskScore, severity_level } = calculateRiskScore(likelihood, impact);

      // 2d. Insert risk
      const { data: newRisk, error: riskInsertErr } = await client
        .from("risks")
        .insert({
          title:              riskTitle,
          description:        `Auto-generated from assessment: "${title.trim()}". Question failed by user.`,
          jncsf_capability:   resolveCapability(capability),
          likelihood,
          impact,
          quantitative_score: riskScore,
          severity_level,
          status:             "Open",
          source:             "Assessment",
          // user_id is intentionally omitted here; the DEFAULT auth.uid() expression
          // on the column + RLS INSERT policy handles assignment automatically.
        })
        .select()
        .maybeSingle();

      if (riskInsertErr) {
        console.error("Submit: risk insert failed:", riskInsertErr);
        // Non-fatal per-question failure — log and continue processing remaining answers
        continue;
      }

      if (newRisk) {
        createdRisks.push(newRisk);

        // 2e. Attempt to create a remediation task assigned to the submitting user.
        // The profiles table must have a row for this user (migration 009 FK).
        // We attempt the insert and swallow the error gracefully if the profile is missing.
        const { data: task, error: taskErr } = await client
          .from("remediation_tasks")
          .insert({
            risk_id:     newRisk.id,
            assigned_to: user.id,
            status:      "Open",
            notes: `Auto-created: address the failed control "${riskTitle}" identified in assessment "${title.trim()}".`,
          })
          .select()
          .maybeSingle();

        if (taskErr) {
          // Profile may not yet exist — log but do not fail the whole submission
          console.error(
            `Submit: remediation task for risk ${newRisk.id} failed:`,
            taskErr
          );
        } else if (task) {
          createdRemediationTasks.push(task);
        }
      }
    }

    // ── Step 3: Persist to assessment_history ─────────────────────────────────

    const { data: historyRecord, error: historyErr } = await client
      .from("assessment_history")
      .insert({
        title:        title.trim(),
        score:        scoreStr,
        completed_by: user.id,
      })
      .select()
      .maybeSingle();

    if (historyErr) {
      // Non-fatal — the risks were already created; log and continue
      console.error("Submit: assessment_history insert failed:", historyErr);
    }

    // ── Step 4: Mark source assessment as Completed ───────────────────────────

    if (assessmentId && typeof assessmentId === "string") {
      const { error: updateErr } = await client
        .from("assessments")
        .update({ status: "Completed" })
        .eq("id", assessmentId.trim());

      if (updateErr) {
        console.error("Submit: assessment status update failed:", updateErr);
        // Non-fatal — history record already saved
      }
    }

    // ── Step 5: Audit log (non-blocking, non-fatal) ───────────────────────────
    //
    // audit_logs.record_id is UUID NOT NULL — use the history record id if we
    // have one, otherwise use a deterministic fallback (the user's own UUID).
    const auditRecordId = historyRecord?.id ?? user.id;

    client
      .from("audit_logs")
      .insert({
        user_id:    user.id,
        action:     "SUBMITTED_ASSESSMENT",
        table_name: "assessment_history",
        record_id:  auditRecordId,
        ip_address: getClientIp(request),
      })
      .then(({ error: auditErr }) => {
        if (auditErr) console.error("Audit log failed:", auditErr);
      });

    // ── Step 6: Return consolidated result ────────────────────────────────────

    return new Response(
      JSON.stringify({
        success:              true,
        // Scoring summary
        score,
        score_display:        scoreStr,
        status,
        passed,
        total_questions:      totalQuestions,
        passed_count:         passedCount,
        failed_count:         failedAnswers.length,
        pass_threshold:       PASS_THRESHOLD,
        // Generated artefacts
        created_risks:        createdRisks,
        remediation_tasks:    createdRemediationTasks,
        assessment_history_id: historyRecord?.id ?? null,
        // Human-readable summary
        message: `Assessment graded: ${scoreStr} — ${status}. ${createdRisks.length} risk(s) and ${createdRemediationTasks.length} remediation task(s) generated.`,
      }),
      { status: 201, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 POST /api/assessments/submit — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/assessments/submit ─────────────────────────────────────────

export function OPTIONS() {
  return handleCORSPreflight();
}
