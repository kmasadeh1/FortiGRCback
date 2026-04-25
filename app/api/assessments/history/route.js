import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { authenticateRequest } from "@/lib/authGuard";

// ─── GET /api/assessments/history ────────────────────────────────────────────

/**
 * Returns the authenticated user's completed assessment history
 * from the `assessment_history` table (migration 011), ordered newest-first.
 *
 * Response shape:
 * {
 *   history: [
 *     {
 *       id:           string (UUID),
 *       title:        string,
 *       score:        string,       // e.g. "80.0%" — stored as text
 *       passed:       boolean,      // derived server-side from score >= PASS_THRESHOLD
 *       completed_at: string (ISO timestamp)
 *     }
 *   ],
 *   total: number
 * }
 *
 * Requires: Authorization: Bearer <access_token>
 */

// Minimum score percentage required to consider an assessment passed
const PASS_THRESHOLD = 70;

/**
 * Parses a score string like "80.0%" into a numeric percentage.
 * Returns null if the string cannot be parsed.
 *
 * @param {string | null} scoreStr
 * @returns {number | null}
 */
function parseScorePercent(scoreStr) {
  if (!scoreStr || typeof scoreStr !== "string") return null;
  const numeric = parseFloat(scoreStr.replace("%", "").trim());
  return isNaN(numeric) ? null : numeric;
}

export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client, user } = auth;

    // Query the dedicated history table — scoped to this user via `completed_by`
    const { data, error } = await client
      .from("assessment_history")
      .select("id, title, score, completed_by, completed_at")
      .eq("completed_by", user.id)
      .order("completed_at", { ascending: false });

    if (error) {
      console.error("🔥 GET /api/assessments/history — Supabase error:", error);
      return corsResponse(
        { error: "Failed to fetch assessment history", details: error.message },
        500
      );
    }

    // Derive pass/fail server-side so the frontend only renders what it receives
    const history = (data || []).map((row) => {
      const scoreNum = parseScorePercent(row.score);
      return {
        id: row.id,
        title: row.title,
        score: row.score ?? "N/A",
        score_numeric: scoreNum,
        passed: scoreNum !== null ? scoreNum >= PASS_THRESHOLD : null,
        completed_at: row.completed_at,
      };
    });

    return new Response(
      JSON.stringify({ history, total: history.length }),
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 GET /api/assessments/history — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/assessments/history ────────────────────────────────────────

export function OPTIONS() {
  return handleCORSPreflight();
}
