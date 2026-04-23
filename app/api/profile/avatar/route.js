import { authenticateRequest } from "@/lib/authGuard";
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB for avatars
const BUCKET_NAME = "avatars";

/**
 * POST /api/profile/avatar
 *
 * Handles file uploads for profile avatars.
 * Expects multipart/form-data with a `file` field.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return corsResponse({ error: "No active session found" }, 401);
    }
    const { client, user } = auth;

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return corsResponse({ error: "Invalid form data. Expected multipart/form-data." }, 400);
    }

    const file = formData.get("file");

    if (!file || !(file instanceof File) || file.size === 0) {
      return corsResponse({ error: "file is required and must not be empty." }, 400);
    }

    if (file.size > MAX_FILE_SIZE) {
      return corsResponse({ error: `File size exceeds the maximum allowed (${MAX_FILE_SIZE / 1024 / 1024} MB).` }, 400);
    }

    // Ensure bucket exists or handled gracefully (we assume standard Supabase avatars pattern)
    // Upload image directly under the user's UUID so they own their folder
    const fileExt = file.name.split('.').pop()?.toLowerCase() || 'jpg';
    const storagePath = `${user.id}/avatar-${Date.now()}.${fileExt}`;
    const fileBuffer = await file.arrayBuffer();

    const { data: uploadData, error: uploadError } = await client.storage
      .from(BUCKET_NAME)
      .upload(storagePath, fileBuffer, {
        contentType: file.type || "image/jpeg",
        upsert: true,
      });

    if (uploadError) {
      console.error("🔥 BACKEND CRASH ERROR (Storage):", uploadError);
      return corsResponse({ error: "Avatar upload failed", details: uploadError.message }, 500);
    }

    // Generate public URL (assuming avatars bucket is public like standard patterns dictact) 
    // If private, you'd use getSignedUrl, but avatars are natively meant to be publicly readable
    const { data: { publicUrl } } = client.storage.from(BUCKET_NAME).getPublicUrl(uploadData.path);

    // Automatically bind the new URL to their active profile
    const { data: profileRecord, error: profileErr } = await client
      .from("profiles")
      .upsert({ id: user.id, avatar_url: publicUrl })
      .select()
      .single();

    if (profileErr) {
       console.error("🔥 BACKEND CRASH ERROR (DB Update):", profileErr);
       return corsResponse({ error: "Failed to link avatar to profile", details: profileErr.message }, 500);
    }

    return new Response(JSON.stringify({ 
      message: "Avatar uploaded successfully.", 
      avatar_url: publicUrl,
      profile: profileRecord
    }), { status: 201, headers: CORS_HEADERS });

  } catch (error) {
    console.error("🔥 BACKEND CRASH ERROR:", error);
    return corsResponse({ success: false, error: error.message || "Unknown error" }, 500);
  }
}

export function OPTIONS() {
  return handleCORSPreflight();
}
