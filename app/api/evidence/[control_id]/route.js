import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { authenticateRequest } from "@/lib/authGuard";

/** Supabase Storage bucket name for all evidence files. */
const BUCKET_NAME = "fortigrc-evidence";

/**
 * Expiry in seconds for each signed URL.
 * 300 seconds (5 minutes) gives the frontend enough time to display or
 * trigger a download without exposing the URL for longer than necessary.
 */
const SIGNED_URL_EXPIRY_SECONDS = 300;

// ─── GET /api/evidence/[control_id] ──────────────────────────────────────────

/**
 * Returns all evidence records for a given compliance control,
 * each enriched with a short-lived signed download URL.
 *
 * URL: GET /api/evidence/<compliance_control_uuid>
 *
 * Response (200):
 * [
 *   {
 *     id:           string (UUID),
 *     control_id:   string,
 *     file_name:    string,
 *     file_url:     string  (storage path — for reference only),
 *     uploaded_by:  string,
 *     created_at:   string,
 *     download_url: string | null   (signed URL valid for SIGNED_URL_EXPIRY_SECONDS)
 *   }
 * ]
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request, context) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse(
        { error: "Authentication required. Provide a valid Bearer token." },
        401
      );
    }

    const { client } = auth;

    // Next.js 15: params is a Promise — must be awaited
    const { control_id } = await context.params;

    if (!control_id || typeof control_id !== "string") {
      return corsResponse({ error: "Missing or invalid control_id in URL." }, 400);
    }

    // ── Fetch evidence records from the database ──────────────────────────────

    const { data: records, error: dbError } = await client
      .from("evidence")
      .select("id, control_id, file_name, file_url, uploaded_by, created_at")
      .eq("control_id", control_id)
      .order("created_at", { ascending: false });

    if (dbError) {
      console.error(
        `🔥 GET /api/evidence/${control_id} — DB error:`,
        dbError
      );
      return corsResponse(
        { error: "Failed to fetch evidence records", details: dbError.message },
        500
      );
    }

    if (!records || records.length === 0) {
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: CORS_HEADERS,
      });
    }

    // ── Generate batch signed URLs ────────────────────────────────────────────
    //
    // createSignedUrls accepts an array of storage paths and returns a matching
    // array. We use `find` by path to safely map URLs back to their records even
    // if the bucket returns them in a different order.

    const storagePaths = records.map((r) => r.file_url);

    const { data: signedUrls, error: signError } = await client.storage
      .from(BUCKET_NAME)
      .createSignedUrls(storagePaths, SIGNED_URL_EXPIRY_SECONDS);

    if (signError) {
      console.error(
        `GET /api/evidence/${control_id} — Signed URL batch error:`,
        signError
      );
      // Non-fatal: return records with null download_url so the frontend
      // can still display the file list and handle the missing link gracefully.
    }

    // ── Merge signed URLs into the records ────────────────────────────────────

    const enriched = records.map((record) => {
      const signedDoc = (signedUrls || []).find((s) => s.path === record.file_url);
      return {
        ...record,
        download_url: signedDoc?.signedUrl ?? null,
      };
    });

    return new Response(JSON.stringify(enriched), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (err) {
    console.error("🔥 GET /api/evidence/[control_id] — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/evidence/[control_id] ──────────────────────────────────────

export function OPTIONS() {
  return handleCORSPreflight();
}
