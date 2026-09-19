// const axios = require('axios');

const BASE_URL = process.env.DETECTION_SERVICE_URL; // e.g. https://sih26106-detection.onrender.com

// Currently tunneled via ngrok (running on a teammate's laptop, not
// deployed to Render like the other two services) — ngrok's free tier
// sometimes serves an interstitial warning page to what it detects as
// browser-like traffic. Server-to-server axios calls usually bypass this
// automatically, but this header is cheap insurance either way. NOTE: the
// bigger fragility here is that ngrok's URL changes every time that
// tunnel restarts — DETECTION_SERVICE_URL on Render needs updating any
// time that happens, independent of any code issue.
const NGROK_HEADERS = { 'ngrok-skip-browser-warning': 'true' };

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
      // Confirmed via a live 422 from /debug/services: their Pydantic model
      // wants the field named "body" (loc: ["body", "body"]) — not
      // "rawEmail". sender/subject are sent too in case their model accepts
      // them as optional context; harmless if ignored.
      body: caseInput.rawEmail
    },
    {
      headers: NGROK_HEADERS,
      timeout: 30_000
    }
  );

  // Confirmed response shape from Swagger (ClassificationOutput):
  // { classification, confidence_score, matched_indicators, processed_at }
  return data;
}

/**
 * anchorCase(caseId, caseDocument)
 * Called only from orchestrator.confirmAndAnchor, itself only reachable via
 * the admin-gated POST /api/cases/:id/confirm route.
 *
 * Request shape CONFIRMED (CaseAnchorRequest): { case_id, case_document }.
 * Send the FULL case record as-is — the service excludes blockchain_hash/
 * blockchain_tx_id/anchored_at/_id/__v from its own hash computation
 * automatically, so no reshaping needed on our end.
 *
 * Response shape CONFIRMED: { blockchain_hash, blockchain_tx_id, anchored_at }
 * — this IS the authoritative hash now; we no longer compute our own
 * locally (see orchestrator.confirmAndAnchor).
 *
 * Calling this twice for the same case_id returns HTTP 409 (confirmed) —
 * handled here by falling back to /verify to retrieve the existing anchor's
 * details, so the caller never has to think about this edge case.
 */
async function anchorCase(caseId, caseDocument) {
  try {
    const { data } = await axios.post(
      `${BASE_URL}/anchor`,
      { case_id: caseId, case_document: caseDocument },
      { headers: NGROK_HEADERS, timeout: 20_000 }
    );
    return {
      blockchain_hash: data.blockchain_hash,
      blockchain_tx_id: data.blockchain_tx_id,
      anchored_at: new Date(data.anchored_at),
      alreadyAnchored: false
    };
  } catch (err) {
    if (err.response?.status === 409) {
      // Already anchored — /verify doesn't return a tx_id, only hash + timestamp.
      const verifyResult = await verifyCase(caseId, caseDocument);
      return {
        blockchain_hash: verifyResult.onchain_hash,
        blockchain_tx_id: null, // genuinely unavailable from /verify — known gap in this fallback path
        anchored_at: new Date(verifyResult.onchain_timestamp),
        alreadyAnchored: true,
        verify: verifyResult
      };
    }
    throw err;
  }
}

/**
 * verifyCase(caseId, caseDocument)
 * Tamper-check: recomputes the hash of caseDocument NOW and compares
 * against what was anchored on-chain at confirm time.
 *
 * Response CONFIRMED: { match, computed_hash, onchain_hash, onchain_timestamp, anchored_by }
 * Used both as the 409 fallback inside anchorCase, and directly from
 * POST /api/cases/:id/verify for an on-demand "verified ✓" check.
 */
async function verifyCase(caseId, caseDocument) {
  const { data } = await axios.post(
    `${BASE_URL}/verify`,
    { case_id: caseId, case_document: caseDocument },
    { headers: NGROK_HEADERS, timeout: 20_000 }
  );
  return data;
}

module.exports = { analyze, anchorCase, verifyCase };