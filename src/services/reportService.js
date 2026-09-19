/**
 * The forensics engineer confirmed POST /report never existed on any
 * microservice — report assembly was always meant to be a Node-side
 * orchestration concern (per their explicit recommendation), since no
 * single Python service sees detection + forensics + enrichment + case
 * metadata together the way this backend already does.
 *
 * Good news: by the time this runs, everything needed is ALREADY sitting
 * on the Case document — this is pure assembly/formatting, no external
 * calls, no new data to fetch.
 */

/**
 * assembleFiveStageReport(caseDoc)
 * Returns a plain JSON object covering all 5 stages: submission, detection,
 * forensics, enrichment, confirmation — plus the full timeline. This is
 * stored on caseDoc.report_data and also returned directly in the
 * POST /cases/:id/report response.
 *
 * NOTE: this produces structured JSON, not a PDF. No PDF-generation
 * library is wired in yet — if a downloadable PDF is a hard requirement,
 * that's a separate, additional piece of work (e.g. pdfkit or puppeteer
 * rendering this same data), not something this function does today.
 */
function assembleFiveStageReport(caseDoc) {
  return {
    case_id: caseDoc._id.toString(),
    generated_at: new Date().toISOString(),

    stage_1_submission: {
      sender: caseDoc.sender,
      recipients: caseDoc.recipients,
      subject: caseDoc.subject,
      channel: caseDoc.channel,
      submitted_at: caseDoc.createdAt
    },

    stage_2_detection: caseDoc.detection || null,
    stage_3_forensics: caseDoc.forensics || null,
    stage_4_enrichment: caseDoc.enrichment || null,

    stage_5_confirmation: {
      confirmed_by: caseDoc.confirmed_by,
      confirmed_at: caseDoc.confirmed_at,
      blockchain_hash: caseDoc.blockchain_hash,
      blockchain_tx_id: caseDoc.blockchain_tx_id,
      anchored_at: caseDoc.anchored_at
    },

    campaign_id: caseDoc.campaignId,
    status: caseDoc.status,
    timeline: caseDoc.timeline
  };
}

module.exports = { assembleFiveStageReport };