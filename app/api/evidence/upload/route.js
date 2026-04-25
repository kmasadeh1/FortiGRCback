import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";
import { authenticateRequest } from "@/lib/authGuard";

// ─── Constants ────────────────────────────────────────────────────────────────

/** Maximum allowed file size in bytes (10 MB). */
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;

/** Supabase Storage bucket name for all evidence files. */
const BUCKET_NAME = "fortigrc-evidence";

/**
 * Strict server-side MIME type allowlist.
 * Any type not in this set is rejected with a 400 before the file is uploaded.
 * The readable label is returned in error messages so the frontend can display it.
 */
const ALLOWED_MIME_TYPES = new Map([
  ["application/pdf",                                                           "PDF"],
  ["image/jpeg",                                                                "JPEG image"],
  ["image/jpg",                                                                 "JPEG image"],
  ["image/png",                                                                 "PNG image"],
  ["image/webp",                                                                "WebP image"],
  ["image/gif",                                                                 "GIF image"],
  ["application/msword",                                                        "Word document (.doc)"],
  ["application/vnd.openxmlformats-officedocument.wordprocessingml.document",  "Word document (.docx)"],
  ["application/vnd.ms-excel",                                                  "Excel spreadsheet (.xls)"],
  ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",        "Excel spreadsheet (.xlsx)"],
  ["text/plain",                                                                "Plain text file"],
]);

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Sanitises a filename so it can be stored safely in a URL path.
 * Replaces anything that is not an alphanumeric character, hyphen,
 * underscore, or period with an underscore.
 *
 * @param {string} originalName
 * @returns {string}
 */
function sanitizeFileName(originalName) {
  return originalName.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Builds the storage path for an evidence file.
 * Format: controls/<control_id>/<timestamp>-<sanitized_name>
 *
 * @param {string} controlId
 * @param {string} originalName
 * @returns {string}
 */
function buildStoragePath(controlId, originalName) {
  const safe = sanitizeFileName(originalName);
  return `controls/${controlId}/${Date.now()}-${safe}`;
}

// ─── POST /api/evidence/upload ────────────────────────────────────────────────

/**
 * Accepts a multipart/form-data file upload and stores it securely in
 * Supabase Storage, then creates an evidence database record.
 *
 * Form fields:
 *   file        (File, required)        — the file to upload
 *   control_id  (string/UUID, required) — the compliance control this evidence supports
 *   title       (string, optional)      — a human-readable label for the evidence document
 *
 * Server-side validations (all applied before any upload attempt):
 *   - `file` must be present and non-empty.
 *   - File size must not exceed MAX_FILE_SIZE_BYTES (10 MB).
 *   - MIME type must be in the ALLOWED_MIME_TYPES allowlist.
 *   - `control_id` must be present and a non-empty string.
 *
 * Response (201):
 * {
 *   message:      string,
 *   record: {
 *     id:           string (UUID),
 *     control_id:   string,
 *     file_name:    string,
 *     file_url:     string  (storage path — use /evidence/[control_id] for signed URL)
 *     uploaded_by:  string,
 *     created_at:   string
 *   },
 *   download_url: string  (60-second signed URL for immediate use)
 * }
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

    // ── Parse multipart form data ─────────────────────────────────────────────

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return corsResponse(
        { error: "Invalid request", details: "Expected multipart/form-data." },
        400
      );
    }

    const file       = formData.get("file");
    const control_id = formData.get("control_id");
    const title      = formData.get("title");

    // ── Server-side validation (all checks before any I/O) ────────────────────

    const errors = [];

    // File presence and emptiness
    if (!file || !(file instanceof File)) {
      errors.push("file is required.");
    } else {
      if (file.size === 0) {
        errors.push("The uploaded file is empty.");
      }

      // Size check
      if (file.size > MAX_FILE_SIZE_BYTES) {
        errors.push(
          `File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds the maximum allowed size of ${MAX_FILE_SIZE_BYTES / 1024 / 1024} MB.`
        );
      }

      // MIME type check — strict allowlist enforced server-side
      const mimeType = (file.type || "").toLowerCase().trim();
      if (!ALLOWED_MIME_TYPES.has(mimeType)) {
        const allowed = [...ALLOWED_MIME_TYPES.values()].join(", ");
        errors.push(
          `File type "${mimeType || "unknown"}" is not permitted. Allowed types: ${allowed}.`
        );
      }
    }

    // control_id validation
    if (!control_id || typeof control_id !== "string" || control_id.trim().length === 0) {
      errors.push("control_id is required and must be a valid UUID string.");
    }

    if (errors.length > 0) {
      return corsResponse({ error: "Validation failed", details: errors }, 400);
    }

    // ── Upload to Supabase Storage ────────────────────────────────────────────

    const storagePath = buildStoragePath(control_id.trim(), file.name);
    const fileBuffer  = await file.arrayBuffer();

    const { data: uploadData, error: uploadError } = await client.storage
      .from(BUCKET_NAME)
      .upload(storagePath, fileBuffer, {
        contentType: file.type,
        upsert:      false,      // never silently overwrite — fail if path exists
      });

    if (uploadError) {
      console.error("🔥 POST /api/evidence/upload — Storage error:", uploadError);
      return corsResponse(
        { error: "File upload to storage failed", details: uploadError.message },
        500
      );
    }

    // ── Insert evidence record into the database ──────────────────────────────

    const { data: dbRecord, error: dbError } = await client
      .from("evidence")
      .insert({
        control_id:  control_id.trim(),
        file_name:   file.name,               // original filename preserved for display
        file_url:    uploadData.path,          // storage path used to generate signed URLs
        uploaded_by: user.id,
      })
      .select()
      .maybeSingle();

    if (dbError) {
      console.error("🔥 POST /api/evidence/upload — DB insert error:", dbError);

      // Roll back: remove the orphaned file from storage so the bucket stays clean
      const { error: cleanupErr } = await client.storage
        .from(BUCKET_NAME)
        .remove([uploadData.path]);

      if (cleanupErr) {
        console.error(
          "POST /api/evidence/upload — Storage cleanup failed after DB error:",
          cleanupErr
        );
      }

      return corsResponse(
        { error: "Failed to save evidence record", details: dbError.message },
        500
      );
    }

    if (!dbRecord) {
      return corsResponse(
        { error: "Failed to save evidence record", details: "No record returned after insert." },
        500
      );
    }

    // ── Generate a short-lived signed URL for immediate use ───────────────────
    //
    // The storage bucket is private. We generate a 60-second signed URL so
    // the caller can immediately open or display the uploaded file.
    // For subsequent access use GET /api/evidence/[control_id].

    const { data: signedData, error: signError } = await client.storage
      .from(BUCKET_NAME)
      .createSignedUrl(uploadData.path, 60);

    const downloadUrl = signError ? null : (signedData?.signedUrl ?? null);

    if (signError) {
      console.warn("POST /api/evidence/upload — Signed URL generation failed:", signError);
      // Non-fatal — the record was saved successfully; the caller can still use
      // GET /api/evidence/[control_id] to retrieve signed URLs later.
    }

    return new Response(
      JSON.stringify({
        message:      "Evidence uploaded and saved successfully.",
        record:       dbRecord,
        download_url: downloadUrl,
      }),
      { status: 201, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error("🔥 POST /api/evidence/upload — Unhandled error:", err);
    return corsResponse(
      { error: "Internal server error", details: err.message || "Unknown error" },
      500
    );
  }
}

// ─── OPTIONS /api/evidence/upload ────────────────────────────────────────────

export function OPTIONS() {
  return handleCORSPreflight();
}
