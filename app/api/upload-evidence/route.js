import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

// Valid entity types for evidence uploads
const VALID_ENTITY_TYPES = ["Risk", "Compliance"];

// Maximum file size: 10 MB
const MAX_FILE_SIZE = 10 * 1024 * 1024;

// Supabase Storage bucket name
const BUCKET_NAME = "fortigrc-evidence";

/**
 * POST /api/upload-evidence
 *
 * Handles file uploads for evidence documentation.
 *
 * Request: multipart/form-data with fields:
 *   - file        (File, required)
 *   - entity_id   (string/UUID, required — the linked Risk or Compliance ID)
 *   - entity_type (string, required — 'Risk' or 'Compliance')
 *
 * Requires: Authorization: Bearer <access_token>
 *
 * Flow:
 *   1. Authenticate the user
 *   2. Validate the form fields
 *   3. Upload the file to Supabase Storage bucket `fortigrc-evidence`
 *   4. Get the public URL of the uploaded file
 *   5. Insert a record into `evidence_documentation`
 *   6. Return the DB record + file URL
 */
export async function POST(request) {
  try {
    // --- Authenticate --------------------------------------------------------
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;

    // --- Parse multipart form data ------------------------------------------
    let formData;
    try {
      formData = await request.formData();
    } catch {
      return NextResponse.json(
        { error: "Invalid form data. Expected multipart/form-data." },
        { status: 400 }
      );
    }

    const file = formData.get("file");
    const entity_id = formData.get("entity_id");
    const entity_type = formData.get("entity_type");

    // --- Validate fields -----------------------------------------------------
    const errors = [];

    if (!file || !(file instanceof File) || file.size === 0) {
      errors.push("file is required and must not be empty.");
    } else if (file.size > MAX_FILE_SIZE) {
      errors.push(
        `File size exceeds the maximum allowed (${MAX_FILE_SIZE / 1024 / 1024} MB).`
      );
    }

    if (!entity_id || typeof entity_id !== "string" || entity_id.trim().length === 0) {
      errors.push("entity_id is required and must be a valid UUID string.");
    }

    if (!entity_type || !VALID_ENTITY_TYPES.includes(entity_type)) {
      errors.push(
        `entity_type is required and must be one of: ${VALID_ENTITY_TYPES.join(", ")}.`
      );
    }

    if (errors.length > 0) {
      return NextResponse.json(
        { error: "Validation failed", details: errors },
        { status: 400 }
      );
    }

    // --- Upload file to Supabase Storage ------------------------------------
    const fileName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_"); // sanitize
    const storagePath = `${entity_type.toLowerCase()}s/${entity_id.trim()}-${Date.now()}-${fileName}`;

    // Convert the File to an ArrayBuffer for the Supabase upload
    const fileBuffer = await file.arrayBuffer();

    const { data: uploadData, error: uploadError } = await client.storage
      .from(BUCKET_NAME)
      .upload(storagePath, fileBuffer, {
        contentType: file.type || "application/octet-stream",
        upsert: false,
      });

    if (uploadError) {
      console.error("Supabase Storage upload error:", uploadError);
      return NextResponse.json(
        {
          error: "File upload failed",
          details: uploadError.message,
        },
        { status: 500 }
      );
    }

    // --- Get the public URL of the uploaded file ----------------------------
    const { data: urlData } = client.storage
      .from(BUCKET_NAME)
      .getPublicUrl(uploadData.path);

    const file_url = urlData?.publicUrl || null;

    // --- Insert record into evidence_documentation --------------------------
    const { data: dbRecord, error: dbError } = await client
      .from("evidence_documentation")
      .insert({
        entity_id: entity_id.trim(),
        entity_type,
        file_name: file.name, // original file name (unsanitized for display)
        file_url,
      })
      .select()
      .single();

    if (dbError) {
      console.error("Supabase DB insert error:", dbError);

      // Attempt to clean up the uploaded file since the DB insert failed
      const { error: deleteError } = await client.storage
        .from(BUCKET_NAME)
        .remove([uploadData.path]);

      if (deleteError) {
        console.error(
          "Failed to clean up orphaned file after DB error:",
          deleteError
        );
      }

      return NextResponse.json(
        {
          error: "Failed to save evidence record",
          details: dbError.message,
        },
        { status: 500 }
      );
    }

    // --- Return success response --------------------------------------------
    return NextResponse.json(
      {
        message: "Evidence uploaded successfully.",
        record: dbRecord,
        file_url,
      },
      { status: 201 }
    );
  } catch (err) {
    console.error("Unexpected error in POST /api/upload-evidence:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
