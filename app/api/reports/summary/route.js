import { NextResponse } from 'next/server';
import { getSupabase } from '@/lib/supabaseClient';

export async function GET() {
  try {
    const supabase = getSupabase();

    // 1. Fetch risks
    const { data: risks, error: risksError } = await supabase
      .from('risks')
      .select('quantitative_score, is_excepted');

    if (risksError) {
      throw new Error(`Failed to fetch risks: ${risksError.message}`);
    }

    // Filter out excepted risks
    const activeRisks = risks.filter(r => r.is_excepted !== true);

    const totalRisks = activeRisks.length;
    // Calculate total financial exposure (assuming quantitative_score is numeric)
    const totalExposure = activeRisks.reduce((sum, risk) => {
      const score = Number(risk.quantitative_score) || 0;
      return sum + score;
    }, 0);

    // 2. Fetch compliance controls
    const { data: controls, error: controlsError } = await supabase
      .from('compliance_controls')
      .select('is_compliant');

    if (controlsError) {
      throw new Error(`Failed to fetch compliance controls: ${controlsError.message}`);
    }

    const totalControls = controls.length;
    // Count controls marked as compliant
    const compliantControls = controls.filter(c => c.is_compliant === true).length;

    // Return the aggregated metrics
    return NextResponse.json({
      total_risks: totalRisks,
      total_financial_exposure: totalExposure,
      total_controls: totalControls,
      compliant_controls: compliantControls
    }, { status: 200 });

  } catch (error) {
    console.error('API Error /reports/summary:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
