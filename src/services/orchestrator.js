const detectionService = require('./detectionService');
const forensicsService = require('./forensicsService');
const enrichmentService = require('./enrichmentService');
const campaignClustering = require('./campaignClustering');

/**
 * runAnalysisPipeline(caseDoc)
 *
 * Detection and forensics are independent, so they run in parallel.
 * Enrichment is NOT independent — it needs an origin IP, derived from
 * forensics.relay_path via deriveOriginIp() below (CONFIRMED against
 * forensics' real source — there is no earliest_trustworthy_ip field in
 * the actual API response, despite an earlier written answer describing
 * one; that description was for logic that isn't in the deployed code).
 * If forensics fails, enrichment is skipped entirely (no IP to enrich)
 * rather than guessing — the case simply stays in 'analyzing' with
 * enrichment unset, which allStagesComplete() correctly reflects.
 *
 * Each microservice stamps its OWN processed_at — the orchestrator never
 * invents a timestamp on a service's behalf, it just reads back whatever
 * that service set and appends a timeline entry from it.
 */
async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
  const [detectionResult, forensicsResult] = await Promise.allSettled([
    detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
    forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
  ]);

  if (detectionResult.status === 'fulfilled') {
    caseDoc.detection = detectionResult.value; // includes its own processed_at
    caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
  } else {
    const reason = detectionResult.reason;
    console.error(`[case ${caseDoc._id}] detection failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
  }

  let enrichmentResult = { status: 'skipped' };

  if (forensicsResult.status === 'fulfilled') {
    caseDoc.forensics = forensicsResult.value;
    caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

    const originIp = deriveOriginIp(caseDoc.forensics);
    console.log('[originIp]', originIp, 'hops:',
  JSON.stringify(caseDoc.forensics?.relay_path?.map(h => h.from_ip)));
    enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, originIp));
    if (enrichmentResult.status === 'fulfilled') {
      caseDoc.enrichment = enrichmentResult.value;
      caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
    } else {
      const reason = enrichmentResult.reason;
      console.error(`[case ${caseDoc._id}] enrichment failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
    }
  } else {
    const reason = forensicsResult.reason;
    console.error(`[case ${caseDoc._id}] forensics failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
  }

  // Sort defensively — detection/forensics resolve concurrently and may
  // land out of real-world order, but the report needs entries in true
  // chronological order by the stage's own processed_at.
  caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

  caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

  // Campaign correlation runs after enrichment lands, since it clusters on
  // sender infra (ASN/IP/domain age) as well as content signals.
  if (enrichmentResult.status === 'fulfilled') {
    caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
  }

  await caseDoc.save();
  return caseDoc;
}

/**
 * Field readers — CONFIRMED against the forensics service's actual source
 * code (main.py), not inferred from live responses alone. Real top-level
 * keys are `spf`, `dkim`, `dmarc` (not `spf_result` etc.), each with a
 * `.status` field (not `.result`). The `spf_result`/`.result` fallbacks
 * below are kept only as a defensive leftover in case an older/different
 * deploy is ever live again — the confirmed path is tried first.
 */
function readSpfStatus(forensics) {
  return forensics?.spf?.status ?? forensics?.spf_result?.status ?? forensics?.spf_result?.result;
}
function readDkimStatus(forensics) {
  return forensics?.dkim?.status ?? forensics?.dkim_result?.status ?? forensics?.dkim_result?.result;
}
function readDmarcStatus(forensics) {
  return forensics?.dmarc?.status ?? forensics?.dmarc_result?.status ?? forensics?.dmarc_result?.result;
}

// RFC 1918 / loopback / link-local ranges — CONFIRMED necessary from a real
// example where relay_path[0] (the outermost/oldest hop) was an internal
// relay IP (10.90.19.29, Sparkpost's own infra) rather than a public
// address. The forensics service's own internal origin_ip pick (used to
// feed its SPF check) does NOT filter these out and isn't even exposed in
// the API response anyway — so this filtering happens on our side.
function isPrivateIp(ip) {
  if (!ip) return true;
  return (
    /^10\./.test(ip) ||
    /^127\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    ip === '::1' ||
    /^f[cd][0-9a-f]{2}:/i.test(ip) // IPv6 unique local
  );
}

/**
 * deriveOriginIp(forensics)
 *
 * CONFIRMED from forensics' actual relay_parser.py: relay_path is returned
 * as a FLAT array, already reordered chronologically — index 0 is the
 * OLDEST hop (closest to true origin), not the newest. There is no
 * earliest_trustworthy_ip field in the real API response at all (it was
 * described in an earlier written answer but doesn't exist in the actual
 * deployed code — origin_ip is computed internally by forensics but never
 * surfaced to callers).
 *
 * Walks from index 0 forward and returns the first hop with a real,
 * non-private IP — since the literal first hop can be internal relay
 * infrastructure (confirmed via a real example: Sparkpost's own 10.x relay
 * before the actual public sending IP two hops later). Falls back to
 * hop 0's IP even if private, rather than null, so enrichment still gets
 * something to try rather than being skipped entirely.
 */
function deriveOriginIp(forensics) {
  const hops = Array.isArray(forensics?.relay_path) ? forensics.relay_path : [];
  if (hops.length === 0) return null;

  for (const hop of hops) {
    const ip = hop?.from_ip;
    if (ip && !isPrivateIp(ip)) return ip;
  }

  // Nothing public found — fall back to the first hop's IP anyway (may be
  // private/empty; enrichment already handles that gracefully as "unknown").
  return hops[0]?.from_ip || null;
}

// Small helper so a single awaited call can be treated the same way as an
// allSettled entry ({ status, value }) without pulling in a second array.
async function promiseSettle(promise) {
  try {
    const value = await promise;
    return { status: 'fulfilled', value };
  } catch (err) {
    return { status: 'rejected', reason: err };
  }
}

function allStagesComplete(caseDoc) {
  return Boolean(
    caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
  );
}

function timelineEntryFor(stage, stageData) {
  const summaries = {
    detection: `Detection: ${stageData.classification ?? 'unknown'} (confidence ${stageData.confidence_score})`,
    forensics: `Forensics: SPF=${readSpfStatus(stageData)} DKIM=${readDkimStatus(stageData)} DMARC=${readDmarcStatus(stageData)}`,
    enrichment: `Enrichment: ${stageData.infrastructure_type || 'unknown infra'} (${stageData.geolocation?.country || 'unknown location'})`
  };
  return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
}

/**
 * confirmAndAnchor(caseDoc, { confirmedBy, notes })
 *
 * Called only from the admin-gated POST /api/cases/:id/confirm route.
 *
 * REWORKED per the detection engineer's confirmed answers: we send the
 * FULL case document (not a hand-picked snapshot) — the service excludes
 * blockchain_hash/blockchain_tx_id/anchored_at/_id/__v from its own hash
 * computation automatically. We no longer compute our own hash locally;
 * blockchain_hash is now whatever the service's /anchor response returns
 * (the authoritative value), stored directly.
 */
async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
  const caseDocument = caseDoc.toObject();

  const anchorResult = await detectionService.anchorCase(caseDoc._id.toString(), caseDocument);

  caseDoc.status = 'confirmed';
  caseDoc.blockchain_hash = anchorResult.blockchain_hash;
  caseDoc.blockchain_tx_id = anchorResult.blockchain_tx_id;
  caseDoc.anchored_at = anchorResult.anchored_at;
  caseDoc.confirmed_by = confirmedBy;
  caseDoc.confirmed_at = new Date();
  caseDoc.timeline.push({
    stage: 'confirmed',
    actor: confirmedBy,
    summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
    at: caseDoc.confirmed_at
  });

  await caseDoc.save();
  return { updatedCase: caseDoc, ...anchorResult };
}

module.exports = { runAnalysisPipeline, confirmAndAnchor };