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
 * detectionRiskContribution(detection)
 *
 * confidence_score means "how confident the model is in the classification
 * it assigned" — NOT "how risky this email is." Those are the same
 * direction for phishing/bec/suspicious (more confident phishing = more
 * risk), but INVERTED for legitimate (more confident legitimate = LESS
 * risk). The old code used confidence_score directly for every class,
 * which meant a confidently-legitimate email with a high confidence_score
 * pushed the risk score UP instead of down — confirmed on a real case:
 * classification 'legitimate' at 91.2% confidence, forensics spoofing risk
 * 24, produced round((91 + 24) / 2) = 58 = MEDIUM, for an email that was
 * both correctly classified as legitimate AND passed forensics cleanly.
 */
function detectionRiskContribution(detection) {
  const classification = detection?.classification;
  const confidence = detection?.confidence_score;
  if (typeof confidence !== 'number') return 0;

  if (classification === 'legitimate') {
    // Invert: 91.2% confident legitimate -> ~9 points of risk, not 91.
    return 100 - confidence;
  }

  // phishing | bec | suspicious | anything undocumented: confidence_score
  // IS already a threat-confidence value here, used as-is — unchanged from
  // the original behavior for every class except legitimate.
  return confidence;
}

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
  const confidencePart = Math.round(detectionRiskContribution(detection));
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