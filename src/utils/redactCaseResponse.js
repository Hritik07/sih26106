// /**
//  * This is the ONLY place a reporter-facing response is built. It never
//  * receives or touches the full case object beyond the two numeric inputs
//  * it needs — detection/forensics/enrichment blocks never pass through this
//  * module, so there's no full object being filtered down here; the redacted
//  * shape is all this code is capable of producing in the first place.
//  */

// const BANDS = [
//   { max: 29, label: 'Likely Safe', message: 'No significant threat indicators were found in this email.' },
//   { max: 59, label: 'Suspicious', message: 'Some suspicious signals were detected — treat this email with caution.' },
//   { max: 84, label: 'High Risk', message: 'Multiple strong threat indicators were found in this email.' },
//   { max: 100, label: 'Confirmed Threat Pattern', message: 'This email matches known threat patterns. Do not click links, reply, or download attachments.' }
// ];

// /**
//  * computeRiskScore(detection, forensics)
//  * detection.confidence is 0-1 (from the ML service) — scaled to 0-100.
//  * forensics.spoofing_risk_score is already 0-100 (confirmed field name from
//  * a live forensics response — this service uses snake_case throughout).
//  * Missing inputs default to 0 rather than throwing, so a partial pipeline
//  * (e.g. detection still down) still yields a usable, conservative score.
//  */
// function computeRiskScore(detection, forensics) {
//   const confidencePart = Math.round((detection?.confidence ?? 0) * 100);
//   const spoofingPart = forensics?.spoofing_risk_score ?? 0;
//   const score = Math.round((confidencePart + spoofingPart) / 2);
//   return Math.max(0, Math.min(100, score));
// }

// function bandFor(score) {
//   return BANDS.find((b) => score <= b.max) || BANDS[BANDS.length - 1];
// }

// /**
//  * buildReporterResponse({ caseId, detection, forensics, submittedAt })
//  * The single function every reporter-facing route calls. Returns exactly
//  * the five allowed fields — nothing else can leak through this path.
//  */
// function buildReporterResponse({ caseId, detection, forensics, submittedAt }) {
//   const risk_score = computeRiskScore(detection, forensics);
//   const { label, message } = bandFor(risk_score);

//   return {
//     case_id: caseId,
//     risk_score,
//     risk_label: label,
//     message,
//     submitted_at: submittedAt
//   };
// }

// module.exports = { computeRiskScore, bandFor, BANDS, buildReporterResponse };







/**
 * This is the ONLY place a reporter-facing response is built. It never
 * receives or touches the full case object beyond the two numeric inputs
 * it needs — detection/forensics/enrichment blocks never pass through this
 * module, so there's no full object being filtered down here; the redacted
 * shape is all this code is capable of producing in the first place.
 */

const BANDS = [
  { max: 29, label: 'Likely Safe', message: 'No significant threat indicators were found in this email.' },
  { max: 59, label: 'Suspicious', message: 'Some suspicious signals were detected — treat this email with caution.' },
  { max: 84, label: 'High Risk', message: 'Multiple strong threat indicators were found in this email.' },
  { max: 100, label: 'Confirmed Threat Pattern', message: 'This email matches known threat patterns. Do not click links, reply, or download attachments.' }
];

/**
 * computeRiskScore(detection, forensics)
 * detection.confidence_score is CONFIRMED already 0-100 (one decimal
 * place) — the ML service does the 0-1 → 0-100 scaling internally before
 * returning it. No dual-scale defensive handling needed anymore.
 * forensics.spoofing_risk_score is confirmed 0-100 (unchanged, snake_case).
 * Missing inputs default to 0 rather than throwing, so a partial pipeline
 * (e.g. detection still down) still yields a usable, conservative score.
 */
function computeRiskScore(detection, forensics) {
  const confidencePart = Math.round(detection?.confidence_score ?? 0);
  const spoofingPart = forensics?.spoofing_risk_score ?? 0;
  const score = Math.round((confidencePart + spoofingPart) / 2);
  return Math.max(0, Math.min(100, score));
}

function bandFor(score) {
  return BANDS.find((b) => score <= b.max) || BANDS[BANDS.length - 1];
}

/**
 * buildReporterResponse({ caseId, detection, forensics, submittedAt })
 * The single function every reporter-facing route calls. Returns exactly
 * the five allowed fields — nothing else can leak through this path.
 */
function buildReporterResponse({ caseId, detection, forensics, submittedAt }) {
  const risk_score = computeRiskScore(detection, forensics);
  const { label, message } = bandFor(risk_score);

  return {
    case_id: caseId,
    risk_score,
    risk_label: label,
    message,
    submitted_at: submittedAt
  };
}

module.exports = { computeRiskScore, bandFor, BANDS, buildReporterResponse };