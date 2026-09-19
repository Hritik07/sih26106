// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze(caseDoc),
//     forensicsService.analyzeHeaders(caseDoc)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the IP forensics just extracted — sequential, not parallel.
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, caseDoc.forensics.extractedIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     }
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf} DKIM=${stageData.dkim} DMARC=${stageData.dmarc}`,
//     enrichment: `Enrichment: origin ${stageData.originIp || 'unknown'} (${stageData.geo?.country || 'unknown'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };







// V2 // 











// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze(caseDoc),
//     forensicsService.analyzeHeaders(caseDoc)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     console.error(`[case ${caseDoc._id}] detection failed:`, detectionResult.reason?.message || detectionResult.reason);
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the IP forensics just extracted — sequential, not parallel.
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, caseDoc.forensics.extractedIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, enrichmentResult.reason?.message || enrichmentResult.reason);
//     }
//   } else {
//     console.error(`[case ${caseDoc._id}] forensics failed:`, forensicsResult.reason?.message || forensicsResult.reason);
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf} DKIM=${stageData.dkim} DMARC=${stageData.dmarc}`,
//     enrichment: `Enrichment: origin ${stageData.originIp || 'unknown'} (${stageData.geo?.country || 'unknown'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };



//V3//


// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
//     forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     const reason = detectionResult.reason;
//     console.error(`[case ${caseDoc._id}] detection failed:`, reason?.response?.data || reason?.message || reason);
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the IP forensics just extracted — sequential, not parallel.
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, caseDoc.forensics.extractedIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       const reason = enrichmentResult.reason;
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, reason?.response?.data || reason?.message || reason);
//     }
//   } else {
//     const reason = forensicsResult.reason;
//     console.error(`[case ${caseDoc._id}] forensics failed:`, reason?.response?.data || reason?.message || reason);
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf} DKIM=${stageData.dkim} DMARC=${stageData.dmarc}`,
//     enrichment: `Enrichment: origin ${stageData.originIp || 'unknown'} (${stageData.geo?.country || 'unknown'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };




//V4//



// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
//     forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     const reason = detectionResult.reason;
//     console.error(`[case ${caseDoc._id}] detection failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the IP forensics just extracted — sequential, not parallel.
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, caseDoc.forensics.extractedIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       const reason = enrichmentResult.reason;
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//     }
//   } else {
//     const reason = forensicsResult.reason;
//     console.error(`[case ${caseDoc._id}] forensics failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf} DKIM=${stageData.dkim} DMARC=${stageData.dmarc}`,
//     enrichment: `Enrichment: origin ${stageData.originIp || 'unknown'} (${stageData.geo?.country || 'unknown'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };




// V5 //



// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
//     forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     // TEMP DEBUG — remove once field-name mapping is confirmed correct.
//     console.log(`[case ${caseDoc._id}] detection raw response:`, JSON.stringify(detectionResult.value, null, 2));
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     const reason = detectionResult.reason;
//     console.error(`[case ${caseDoc._id}] detection failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     // TEMP DEBUG — remove once field-name mapping is confirmed correct.
//     console.log(`[case ${caseDoc._id}] forensics raw response:`, JSON.stringify(forensicsResult.value, null, 2));
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the IP forensics just extracted — sequential, not parallel.
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, caseDoc.forensics.extractedIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       // TEMP DEBUG — remove once field-name mapping is confirmed correct.
//       console.log(`[case ${caseDoc._id}] enrichment raw response:`, JSON.stringify(enrichmentResult.value, null, 2));
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       const reason = enrichmentResult.reason;
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//     }
//   } else {
//     const reason = forensicsResult.reason;
//     console.error(`[case ${caseDoc._id}] forensics failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf} DKIM=${stageData.dkim} DMARC=${stageData.dmarc}`,
//     enrichment: `Enrichment: origin ${stageData.originIp || 'unknown'} (${stageData.geo?.country || 'unknown'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };



// V4 // 



// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
//     forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     const reason = detectionResult.reason;
//     console.error(`[case ${caseDoc._id}] detection failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the origin IP — forensics doesn't return one
//     // directly, it's derived from relay_path (the Received-header hop
//     // chain). See deriveOriginIp() below.
//     const originIp = deriveOriginIp(caseDoc.forensics);
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, originIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       const reason = enrichmentResult.reason;
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//     }
//   } else {
//     const reason = forensicsResult.reason;
//     console.error(`[case ${caseDoc._id}] forensics failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// /**
//  * deriveOriginIp(forensics)
//  * forensics.relay_path is the array of Received-header hops (see the real
//  * shape confirmed from a live forensics response). Assumes hops are ordered
//  * closest-to-recipient first and origin last — the standard Received-header
//  * order (top of email = most recent hop). With only one hop (common in
//  * simplified test emails) this is unambiguous either way. Worth confirming
//  * this ordering assumption with the forensics teammate once multi-hop test
//  * data is available.
//  */
// function deriveOriginIp(forensics) {
//   const hops = forensics?.relay_path;
//   if (!hops || hops.length === 0) return null;
//   return hops[hops.length - 1].from_ip || null;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf_result?.status} DKIM=${stageData.dkim_result?.status} DMARC=${stageData.dmarc_result?.status}`,
//     enrichment: `Enrichment: ${stageData.infrastructure_type || 'unknown infra'} (${stageData.geolocation?.country || 'unknown location'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };





// V5 //




// const crypto = require('crypto');
// const detectionService = require('./detectionService');
// const forensicsService = require('./forensicsService');
// const enrichmentService = require('./enrichmentService');
// const campaignClustering = require('./campaignClustering');
// const Case = require('../models/Case');

// /**
//  * runAnalysisPipeline(caseDoc)
//  *
//  * Detection and forensics are independent, so they run in parallel.
//  * Enrichment is NOT independent — it needs the origin IP that forensics
//  * extracts from headers (forensics.extractedIp), so it runs only after
//  * forensics resolves, using that IP rather than re-parsing headers itself.
//  * If forensics fails, enrichment is skipped entirely (no IP to enrich)
//  * rather than guessing — the case simply stays in 'analyzing' with
//  * enrichment unset, which allStagesComplete() correctly reflects.
//  *
//  * Each microservice stamps its OWN processed_at — the orchestrator never
//  * invents a timestamp on a service's behalf, it just reads back whatever
//  * that service set and appends a timeline entry from it.
//  */
// async function runAnalysisPipeline(caseDoc, { rawEmail, headers } = {}) {
//   const [detectionResult, forensicsResult] = await Promise.allSettled([
//     detectionService.analyze({ sender: caseDoc.sender, subject: caseDoc.subject, rawEmail }),
//     forensicsService.analyzeHeaders(caseDoc, rawEmail, headers)
//   ]);

//   if (detectionResult.status === 'fulfilled') {
//     // TEMP DEBUG — remove once detection's real field names are confirmed
//     // and Case.js's detection schema is updated to match (same process we
//     // went through for forensics and enrichment).
//     console.log(`[case ${caseDoc._id}] detection raw response:`, JSON.stringify(detectionResult.value, null, 2));
//     caseDoc.detection = detectionResult.value; // includes its own processed_at
//     caseDoc.timeline.push(timelineEntryFor('detection', caseDoc.detection));
//   } else {
//     const reason = detectionResult.reason;
//     console.error(`[case ${caseDoc._id}] detection failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   let enrichmentResult = { status: 'skipped' };

//   if (forensicsResult.status === 'fulfilled') {
//     caseDoc.forensics = forensicsResult.value;
//     caseDoc.timeline.push(timelineEntryFor('forensics', caseDoc.forensics));

//     // Enrichment depends on the origin IP — forensics doesn't return one
//     // directly, it's derived from relay_path (the Received-header hop
//     // chain). See deriveOriginIp() below.
//     const originIp = deriveOriginIp(caseDoc.forensics);
//     enrichmentResult = await promiseSettle(enrichmentService.enrich(caseDoc, originIp));
//     if (enrichmentResult.status === 'fulfilled') {
//       caseDoc.enrichment = enrichmentResult.value;
//       caseDoc.timeline.push(timelineEntryFor('enrichment', caseDoc.enrichment));
//     } else {
//       const reason = enrichmentResult.reason;
//       console.error(`[case ${caseDoc._id}] enrichment failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//     }
//   } else {
//     const reason = forensicsResult.reason;
//     console.error(`[case ${caseDoc._id}] forensics failed:`, JSON.stringify(reason?.response?.data ?? reason?.message ?? reason, null, 2));
//   }

//   // Sort defensively — detection/forensics resolve concurrently and may
//   // land out of real-world order, but the report needs entries in true
//   // chronological order by the stage's own processed_at.
//   caseDoc.timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

//   caseDoc.status = allStagesComplete(caseDoc) ? 'investigating' : 'analyzing';

//   // Campaign correlation runs after enrichment lands, since it clusters on
//   // sender infra (ASN/IP/domain age) as well as content signals.
//   if (enrichmentResult.status === 'fulfilled') {
//     caseDoc.campaignId = await campaignClustering.assignCampaign(caseDoc);
//   }

//   await caseDoc.save();
//   return caseDoc;
// }

// /**
//  * deriveOriginIp(forensics)
//  * forensics.relay_path is the array of Received-header hops (see the real
//  * shape confirmed from a live forensics response). Assumes hops are ordered
//  * closest-to-recipient first and origin last — the standard Received-header
//  * order (top of email = most recent hop). With only one hop (common in
//  * simplified test emails) this is unambiguous either way. Worth confirming
//  * this ordering assumption with the forensics teammate once multi-hop test
//  * data is available.
//  */
// function deriveOriginIp(forensics) {
//   const hops = forensics?.relay_path;
//   if (!hops || hops.length === 0) return null;
//   return hops[hops.length - 1].from_ip || null;
// }

// // Small helper so a single awaited call can be treated the same way as an
// // allSettled entry ({ status, value }) without pulling in a second array.
// async function promiseSettle(promise) {
//   try {
//     const value = await promise;
//     return { status: 'fulfilled', value };
//   } catch (err) {
//     return { status: 'rejected', reason: err };
//   }
// }

// function allStagesComplete(caseDoc) {
//   return Boolean(
//     caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at
//   );
// }

// function timelineEntryFor(stage, stageData) {
//   const summaries = {
//     detection: `Detection: ${stageData.isPhishing ? stageData.threatType : 'benign'} (confidence ${stageData.confidence})`,
//     forensics: `Forensics: SPF=${stageData.spf_result?.status} DKIM=${stageData.dkim_result?.status} DMARC=${stageData.dmarc_result?.status}`,
//     enrichment: `Enrichment: ${stageData.infrastructure_type || 'unknown infra'} (${stageData.geolocation?.country || 'unknown location'})`
//   };
//   return { stage, actor: 'system', summary: summaries[stage], at: stageData.processed_at || new Date() };
// }

// /**
//  * confirmAndAnchor(caseDoc, { confirmedBy, notes })
//  *
//  * Called only from the admin-gated POST /api/cases/:id/confirm route.
//  * Builds a deterministic snapshot of the finalized case (the three stage
//  * results + confirmation metadata), hashes it, and asks the ML service's
//  * blockchain-anchoring endpoint to anchor that hash on-chain. The hash is
//  * computed here (not by the ML service) so the anchored value provably
//  * matches what's stored in Mongo at confirmation time.
//  */
// async function confirmAndAnchor(caseDoc, { confirmedBy, notes }) {
//   const snapshot = buildAuditSnapshot(caseDoc);
//   const hash = crypto.createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');

//   const { txId, anchoredAt } = await detectionService.anchorHash(hash);

//   caseDoc.status = 'confirmed';
//   caseDoc.blockchain_hash = hash;
//   caseDoc.blockchain_tx_id = txId;
//   caseDoc.anchored_at = anchoredAt;
//   caseDoc.confirmed_by = confirmedBy;
//   caseDoc.confirmed_at = new Date();
//   caseDoc.timeline.push({
//     stage: 'confirmed',
//     actor: confirmedBy,
//     summary: notes ? `Confirmed as threat: ${notes}` : 'Confirmed as threat',
//     at: caseDoc.confirmed_at
//   });

//   await caseDoc.save();
//   return { updatedCase: caseDoc, hash, txId };
// }

// function buildAuditSnapshot(caseDoc) {
//   // Only the fields that must not change silently after anchoring.
//   return {
//     caseId: caseDoc._id.toString(),
//     detection: caseDoc.detection,
//     forensics: caseDoc.forensics,
//     enrichment: caseDoc.enrichment,
//     sender: caseDoc.sender,
//     subject: caseDoc.subject
//   };
// }

// module.exports = { runAnalysisPipeline, confirmAndAnchor };




// V6//




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

    // earliest_trustworthy_ip is computed correctly by forensics itself
    // (skips private/internal IPs) — no hop-indexing needed on our side.
    const originIp = caseDoc.forensics.earliest_trustworthy_ip || null;
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
    // .result, not .status — confirmed from forensics' real source code.
    forensics: `Forensics: SPF=${stageData.spf_result?.result} DKIM=${stageData.dkim_result?.result} DMARC=${stageData.dmarc_result?.result}`,
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