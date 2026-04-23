import { NextResponse } from 'next/server';
import { getSupabase } from '@/lib/supabaseClient';

export async function GET() {
  try {
    const supabase = getSupabase();

    // 1. Fetch all risks
    const { data: risks, error: risksError } = await supabase
      .from('risks')
      .select('id, title, quantitative_score');

    if (risksError) {
      throw new Error(`Failed to fetch risks: ${risksError.message}`);
    }

    // 2. Fetch all compliance controls
    const { data: controls, error: controlsError } = await supabase
      .from('compliance_controls')
      .select('id, risk_id, control_name, is_compliant');

    if (controlsError) {
      throw new Error(`Failed to fetch compliance controls: ${controlsError.message}`);
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

    // 5. Return as a downloadable CSV
    return new NextResponse(csvData, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="FortiGRC_Audit_Report.csv"'
      }
    });

  } catch (error) {
    console.error('API Error /reports/export:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
