/**
 * Calculates the quantitative risk score and determines its severity level
 * based on the Risk Scoring Matrix.
 *
 * @param {number} likelihood - Integer from 1 to 5
 * @param {number} impact - Integer from 1 to 5
 * @returns {{ score: number, severity_level: string }}
 */
export function calculateRiskScore(likelihood, impact) {
  // Ensure we are working with integers
  const l = parseInt(likelihood, 10);
  const i = parseInt(impact, 10);

  const score = l * i;
  let severity_level = 'Low';

  if (score >= 1 && score <= 4) {
    severity_level = 'Low';
  } else if (score >= 5 && score <= 9) {
    severity_level = 'Medium';
  } else if (score >= 10 && score <= 16) {
    severity_level = 'High';
  } else if (score >= 17 && score <= 25) {
    severity_level = 'Critical';
  }

  return { score, severity_level };
}
