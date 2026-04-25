import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

// ─── GET /api/framework/jncf ──────────────────────────────────────────────────

/**
 * Returns the full JNCF framework tree structured hierarchically as:
 *
 *   Domain → Controls
 *
 * The frontend can map over `domains` directly without restructuring.
 *
 * Response shape:
 * {
 *   total_domains:   number,
 *   total_controls:  number,
 *   domains: [
 *     {
 *       id:           string (UUID),
 *       domain_code:  string,
 *       title:        string,
 *       control_count: number,
 *       controls: [
 *         {
 *           id:           string (UUID),
 *           control_code: string,
 *           description:  string
 *         }
 *       ]
 *     }
 *   ]
 * }
 *
 * Controls within each domain are ordered by control_code ascending.
 * Domains are ordered by domain_code ascending.
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

    // ── Fetch domains with nested controls in a single query ─────────────────
    //
    // Supabase PostgREST supports nested selects via foreign-key relationships.
    // jncf_controls.domain_id → jncf_domains.id is the FK defined in migration 006.
    const { data: domains, error } = await client
      .from("jncf_domains")
      .select(
        `
        id,
        domain_code,
        title,
        created_at,
        jncf_controls (
          id,
          control_code,
          description,
          created_at
        )
      `
      )
      .order("domain_code", { ascending: true });

    if (error) {
      console.error("🔥 GET /api/framework/jncf — Supabase error:", error);
      return corsResponse(
        { error: "Failed to fetch JNCF framework data", details: error.message },
        500
      );
    }

    // ── Enrich each domain with aggregated metadata ───────────────────────────
    //
    // Sort controls within each domain by control_code (string sort is fine
    // since codes follow a structured prefix like "1.1", "1.2", etc.).
    const enrichedDomains = (domains || []).map((domain) => {
      const controls = (domain.jncf_controls || []).sort((a, b) =>
        a.control_code.localeCompare(b.control_code, undefined, { numeric: true })
      );

      return {
        id: domain.id,
        domain_code: domain.domain_code,
        title: domain.title,
        control_count: controls.length,
        controls: controls.map(({ id, control_code, description }) => ({
          id,
          control_code,
          description,
        })),
      };
    });

    // ── Top-level aggregates ──────────────────────────────────────────────────
    const totalControls = enrichedDomains.reduce(
      (sum, d) => sum + d.control_count,
      0
    );

    const payload = {
      total_domains: enrichedDomains.length,
      total_controls: totalControls,
      domains: enrichedDomains,
    };

    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/framework/jncf — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/framework/jncf ─────────────────────────────────────────────

/**
 * Handles CORS preflight requests.
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
