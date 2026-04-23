import { NextResponse } from "next/server";
import { getSupabase } from "@/lib/supabaseClient";
import { calculateRiskScore } from "@/lib/riskScoring";
import { handleCORSPreflight, CORS_HEADERS } from "@/lib/cors";

/**
 * POST /api/ingest/vulnerabilities
 *
 * Ingests external vulnerabilities (e.g., from Nessus/OpenVAS)
 * and maps them into the FortiGRC Risk matrix.
 *
 * Header Map:
 *   Authorization: Bearer <INGEST_SECRET>
 */
export async function POST(request) {
  try {
    // 1. Authenticate Request
    const authHeader = request.headers.get("Authorization");
    const secretToken = process.env.INGEST_SECRET;

    if (!authHeader || !authHeader.startsWith("Bearer ") || !secretToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const providedToken = authHeader.split(" ")[1];
    if (providedToken !== secretToken) {
      return NextResponse.json({ error: "Forbidden: Invalid API Key" }, { status: 403 });
    }

    // 2. Parse Payload
    const body = await request.json();
    const { source, vulnerabilities } = body;

    if (!source || typeof source !== "string") {
      return NextResponse.json({ error: "Validation failed: 'source' is required." }, { status: 400 });
    }

    if (!Array.isArray(vulnerabilities)) {
      return NextResponse.json({ error: "Validation failed: 'vulnerabilities' must be an array." }, { status: 400 });
    }

    // 3. Map Vulnerabilities to FortiGRC Risks
    const supabase = getSupabase();
    const recordsToInsert = [];

    for (const vuln of vulnerabilities) {
      // Basic severity heuristic mapping
      let likelihood = 2;
      let impact = 2;

      const sev = (vuln.severity || "").toLowerCase();
      if (sev.includes("critical")) {
        likelihood = 5;
        impact = 5;
      } else if (sev.includes("high")) {
        likelihood = 4;
        impact = 4;
      } else if (sev.includes("medium")) {
        likelihood = 3;
        impact = 3;
      }

      // Automatically recalculate precise internal matrix scores
      const { score, severity_level } = calculateRiskScore(likelihood, impact);

      recordsToInsert.push({
        title: vuln.title || "Unnamed Vulnerability",
        jncsf_capability: "Operations", // Defaulting to Operations for external tech vulnerabilities
        likelihood,
        impact,
        quantitative_score: score,
        severity_level,
        source: source.trim(), // e.g., 'Nessus', 'OpenVAS'
      });
    }

    if (recordsToInsert.length === 0) {
      return NextResponse.json({ success: true, message: "Imported 0 vulnerabilities as new risks." }, { status: 201, headers: CORS_HEADERS });
    }

    // 4. Batch Insert into Database
    const { data, error } = await supabase
      .from("risks")
      .insert(recordsToInsert)
      .select();

    if (error) {
      console.error("Supabase bulk insert error:", error);
      return NextResponse.json({ error: "Failed to ingest vulnerabilities", details: error.message }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: `Imported ${data.length} vulnerabilities as new risks.`
    }, { status: 201, headers: CORS_HEADERS });

  } catch (error) {
    console.error("🔥 INGEST CRASH ERROR:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500, headers: CORS_HEADERS });
  }
}

/**
 * OPTIONS /api/ingest/vulnerabilities
 */
export function OPTIONS() {
  return handleCORSPreflight();
}
