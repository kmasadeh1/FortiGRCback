import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

// Maximum file size: 10 MB
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const BUCKET_NAME = "fortigrc-evidence";

/**
 * POST /api/evidence/upload
 *
 * Handles file uploads for evidence associated with a compliance control.
 *
 * Request: multipart/form-data with fields:
 *   - file        (File, required)
 *   - control_id  (string/UUID, required — the linked Compliance Control ID)
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client, user } = auth;

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return NextResponse.json({ error: "Invalid form data. Expected multipart/form-data." }, { status: 400 });
    }

    const file = formData.get("file");
    const control_id = formData.get("control_id");

    const errors = [];

    if (!file || !(file instanceof File) || file.size === 0) {
      errors.push("file is required and must not be empty.");
    } else if (file.size > MAX_FILE_SIZE) {
      errors.push(`File size exceeds the maximum allowed (${MAX_FILE_SIZE / 1024 / 1024} MB).`);
    }

    if (!control_id || typeof control_id !== "string" || control_id.trim().length === 0) {
      errors.push("control_id is required and must be a valid UUID string.");
    }

    if (errors.length > 0) {
      return NextResponse.json({ error: "Validation failed", details: errors }, { status: 400 });
    }

    // Sanitize file name explicitly to avoid storage conflicts or path injection
    const fileName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
    const storagePath = `controls/${control_id.trim()}/${Date.now()}-${fileName}`;

    const fileBuffer = await file.arrayBuffer();

    const { data: uploadData, error: uploadError } = await client.storage
      .from(BUCKET_NAME)
      .upload(storagePath, fileBuffer, {
        contentType: file.type || "application/octet-stream",
        upsert: false,
      });

    if (uploadError) {
      console.error("Supabase Storage upload error:", uploadError);
      return NextResponse.json({ error: "File upload failed", details: uploadError.message }, { status: 500 });
    }

    // We will save the root storage path so it can be signed later.
    const file_url = uploadData.path;

    const { data: dbRecord, error: dbError } = await client
      .from("evidence")
      .insert({
        control_id: control_id.trim(),
        file_name: file.name,
        file_url,
        uploaded_by: user.id
      })
      .select()
      .single();

    if (dbError) {
      console.error("Supabase DB insert error:", dbError);
      await client.storage.from(BUCKET_NAME).remove([uploadData.path]);
      return NextResponse.json({ error: "Failed to save evidence record", details: dbError.message }, { status: 500 });
    }

    return NextResponse.json({ message: "Evidence uploaded successfully.", record: dbRecord }, { status: 201 });
  } catch (err) {
    console.error("Unexpected error in POST /api/evidence/upload:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
