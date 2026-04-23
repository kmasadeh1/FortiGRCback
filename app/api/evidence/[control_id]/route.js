import { NextResponse } from "next/server";
import { authenticateRequest } from "@/lib/authGuard";

const BUCKET_NAME = "fortigrc-evidence";

/**
 * GET /api/evidence/[control_id]
 *
 * Fetches all evidence records associated with a specific control
 * and generates secure signed URLs for each file for explicit downloads.
 *
 * Requires: Authorization: Bearer <access_token>
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client } = auth;
    const { control_id } = params;

    if (!control_id) {
      return NextResponse.json({ error: "Missing control_id parameter" }, { status: 400 });
    }

    // 1. Fetch the DB records
    const { data: records, error: dbError } = await client
      .from("evidence")
      .select("id, file_name, file_url, uploaded_by, created_at")
      .eq("control_id", control_id)
      .order("created_at", { ascending: false });

    if (dbError) {
      console.error("Supabase DB select error:", dbError);
      return NextResponse.json({ error: "Failed to fetch evidence records", details: dbError.message }, { status: 500 });
    }

    if (!records || records.length === 0) {
      return NextResponse.json([], { status: 200 });
    }

    // 2. Generate securely signed URLs for the frontend to download from the private bucket
    // Extract simply the paths array
    const paths = records.map(record => record.file_url);

    // Create signed URLs valid for 60 seconds (1 minute) for immediate download capability
    const { data: signedUrls, error: signError } = await client.storage
      .from(BUCKET_NAME)
      .createSignedUrls(paths, 60);

    if (signError) {
      console.error("Supabase Storage signing error:", signError);
      return NextResponse.json({ error: "Failed to generate signed URLs", details: signError.message }, { status: 500 });
    }

    // 3. Map the signed URLs back onto the records
    const evidenceWithUrls = records.map((record, index) => {
      // Find the corresponding signed URL object
      const signedDoc = signedUrls.find(s => s.path === record.file_url);
      
      return {
        ...record,
        // Swap file_url with the temporary signed token URL
        download_url: signedDoc?.signedUrl || null
      };
    });

    return NextResponse.json(evidenceWithUrls, { status: 200 });
  } catch (err) {
    console.error(`Unexpected error in GET /api/evidence/[control_id]:`, err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
