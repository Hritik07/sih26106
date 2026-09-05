const axios = require('axios');

const BASE_URL = process.env.DETECTION_SERVICE_URL; // e.g. https://sih26106-detection.onrender.com

/**
 * analyze(caseInput)
 * Calls the ML/NLP fraud-detection microservice. The service itself stamps
 * processed_at (its clock, its responsibility) — the orchestrator/route
 * just relays whatever comes back.
 */
async function analyze(caseInput) {
  const { data } = await axios.post(
    `${BASE_URL}/classify`,
    {
      sender: caseInput.sender,
      subject: caseInput.subject,
      rawEmail: caseInput.rawEmail
    },
    // Bumped to match forensics/enrichment — real ML inference likely takes
    // longer than it looks on quick test payloads. First real test will
    // tell us if this payload shape (JSON, camelCase rawEmail) is even
    // right — forensics turned out to want multipart/file, so don't assume
    // this is correct until confirmed by a real response.
    { timeout: 30_000 }
  );

  // Expected shape from the ML service (UNCONFIRMED — never seen a real
  // response yet): { isPhishing, threatType, confidence, indicators, modelVersion, processed_at }
  return data;
}

/**
 * anchorHash(hash)
 * Called only from orchestrator.confirmAndAnchor, itself only reachable via
 * the admin-gated POST /api/cases/:id/confirm route. Asks the ML service's
 * blockchain layer to anchor a hash the backend already computed.
 */
async function anchorHash(hash) {
  const { data } = await axios.post(`${BASE_URL}/anchor`, { hash }, { timeout: 15_000 });
  // Expected shape: { txId, anchoredAt }
  return { txId: data.txId, anchoredAt: new Date(data.anchoredAt) };
}

module.exports = { analyze, anchorHash };