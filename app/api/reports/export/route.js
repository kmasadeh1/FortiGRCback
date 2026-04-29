import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/authGuard';
import { corsResponse, handleCORSPreflight, CORS_HEADERS } from '@/lib/cors';

export async function GET(request) {
  try {
    // auth.error is a fully-formed NextResponse — propagate it as-is so
    // MFA_REQUIRED and other structured errors reach the client unchanged.
    const auth = await authenticateRequest(request);
    if (auth.error) return auth.error;
    const { client: supabase } = auth;

    // 1. Fetch all risks
    const { data: risks, error: risksError } = await supabase
      .from('risks')
      .select('id, title, quantitative_score');

    if (risksError) {
      // Log the full Supabase error object — .message alone hides the
      // PostgREST error code, hint, and details that reveal the real cause.
      console.error('Export Crash — risks query failed:', {
        message: risksError.message,
        code:    risksError.code,
        details: risksError.details,
        hint:    risksError.hint,
      });
      return corsResponse(
        { error: 'Failed to fetch risks', details: risksError.message },
        500
      );
    }

    // 2. Fetch all compliance controls
    const { data: controls, error: controlsError } = await supabase
      .from('compliance_controls')
      .select('id, risk_id, control_name, is_compliant');

    if (controlsError) {
      console.error('Export Crash — controls query failed:', {
        message: controlsError.message,
        code:    controlsError.code,
        details: controlsError.details,
        hint:    controlsError.hint,
      });
      return corsResponse(
        { error: 'Failed to fetch compliance controls', details: controlsError.message },
        500
      );
    }

    // 3. Prepare CSV Headers
    const headers = [
      'Risk ID',
      'Risk Title',
      'Risk Financial Exposure',
      'Control ID',
      'Control Title',
      'Is Compliant'
    ];
    
    const csvRows = [];
    csvRows.push(headers.join(','));

    // Helper to safely escape CSV values
    const escapeCsv = (val) => {
      if (val === null || val === undefined) return '';
      const strVal = String(val);
      // Escape double quotes by doubling them, wrap in double quotes if it contains commas, quotes, or newlines
      if (/[",\n\r]/.test(strVal)) {
        return `"${strVal.replace(/"/g, '""')}"`;
      }
      return strVal;
    };

    // 4. Map the data together (Left Join mapping from Risks to Controls)
    risks.forEach(risk => {
      // Find all controls associated with this risk
      const riskControls = controls.filter(
        c => c.risk_id === risk.id
      );

      const rId = escapeCsv(risk.id);
      const rTitle = escapeCsv(risk.title);
      const rScore = escapeCsv(risk.quantitative_score);

      if (riskControls.length > 0) {
        riskControls.forEach(control => {
          csvRows.push([
            rId,
            rTitle,
            rScore,
            escapeCsv(control.id),
            escapeCsv(control.control_name),
            control.is_compliant ? 'Yes' : 'No'
          ].join(','));
        });
      } else {
        // Render risk even if it has no controls
        csvRows.push([
          rId,
          rTitle,
          rScore,
          '',
          '',
          ''
        ].join(','));
      }
    });

    const csvData = csvRows.join('\n');

    // 5. Return as a downloadable CSV (include CORS headers so cross-origin
    //    frontends can read the response and trigger the file download)
    return new Response(csvData, {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="FortiGRC_Audit_Report.csv"',
      },
    });

  } catch (error) {
    // Log the complete error object so stack trace and any Supabase fields
    // are visible in the server console (not just the .message string).
    console.error('Export Crash — unhandled exception:', error);
    return corsResponse(
      { error: error.message || 'Internal server error' },
      500
    );
  }
}

// CORS preflight support for cross-origin requests
export function OPTIONS() {
  return handleCORSPreflight();
}
