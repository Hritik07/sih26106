const detectionService = require('./detectionService');
const forensicsService = require('./forensicsService');
const enrichmentService = require('./enrichmentService');
const campaignClustering = require('./campaignClustering');

/**
 * runAnalysisPipeline(caseDoc)
 *
 * Detection and forensics are independent, so they run in parallel.
 * Enrichment is NOT independent — it needs the origin IP, which forensics
 * now hands us directly via forensics.earliest_trustworthy_ip (CONFIRMED
 * correct field — replaces any hop-array-indexing we used to do ourselves).
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
 * The forensics service's response shape has changed multiple times
 * underneath us — three genuinely different variants observed so far
 * across this build (original testing, the engineer's written answer, and
 * a live response after that answer was given, which reverted close to the
 * ORIGINAL shape). Rather than keep chasing each change with more schema
 * edits, these helpers try every known field-name variant in order and use
 * whichever one is actually present — so reading forensics data stays
 * correct across whichever shape happens to be live on a given day,
 * without another round of debugging every time it changes again.
 */
function readSpfStatus(forensics) {
  return forensics?.spf_result?.result ?? forensics?.spf_result?.status ?? forensics?.spf?.status ?? forensics?.spf?.result;
}
function readDkimStatus(forensics) {
  return forensics?.dkim_result?.result ?? forensics?.dkim_result?.status ?? forensics?.dkim?.status ?? forensics?.dkim?.result;
}
function readDmarcStatus(forensics) {
  return forensics?.dmarc_result?.result ?? forensics?.dmarc_result?.status ?? forensics?.dmarc?.status ?? forensics?.dmarc?.result;
}

/**
 * deriveOriginIp(forensics)
 * Tries the newer top-level earliest_trustworthy_ip field first (per the
 * forensics engineer's written answer); falls back to reading the last
 * entry of a flat relay_path array's from_ip (the shape actually observed
 * live, both originally and again after that answer was given); falls back
 * again to the newer nested {hop_count, hops[].ip} shape in case THAT
 * variant shows up on yet another day. Returns null if none of these are
 * present rather than guessing.
 */
function deriveOriginIp(forensics) {
  if (forensics?.earliest_trustworthy_ip) return forensics.earliest_trustworthy_ip;

  const flatHops = Array.isArray(forensics?.relay_path) ? forensics.relay_path : null;
  if (flatHops && flatHops.length > 0) {
    return flatHops[flatHops.length - 1]?.from_ip || flatHops[flatHops.length - 1]?.ip || null;
  }

  const nestedHops = forensics?.relay_path?.hops;
  if (Array.isArray(nestedHops) && nestedHops.length > 0) {
    return nestedHops[0]?.ip || null;
  }

  return null;
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