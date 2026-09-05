const axios = require('axios');
const FormData = require('form-data');

const BASE_URL = process.env.FORENSICS_SERVICE_URL; // e.g. https://sih26106-forensics.onrender.com

/**
 * analyzeHeaders(caseDoc, rawEmail, headers)
 * Calls the header/SPF/DKIM/DMARC forensics microservice.
 *
 * This service expects a real file upload (multipart/form-data, FastAPI
 * UploadFile) under the field name "file" — NOT a JSON body. Sending the
 * raw email as a JSON string field still 422s even when named correctly,
 * because FastAPI's File(...) dependency only looks at multipart parts.
 * sender/caseId/headers ride along as regular form fields; headers is
 * JSON.stringify'd since multipart fields are plain strings.
 */
async function analyzeHeaders(caseDoc, rawEmail, headers) {
  const form = new FormData();
  form.append('file', Buffer.from(rawEmail || '', 'utf-8'), {
    filename: 'email.eml',
    contentType: 'message/rfc822'
  });
  form.append('sender', caseDoc.sender || '');
  if (caseDoc._id) form.append('caseId', caseDoc._id.toString());
  if (headers) form.append('headers', JSON.stringify(headers));

  const { data } = await axios.post(`${BASE_URL}/analyze-headers`, form, {
    headers: form.getHeaders(),
    // Real emails need real SPF/DKIM/DMARC DNS lookups against the actual
    // sending domain — much slower than the "none"/instant response our
    // fake test domain got. 10s was fine for synthetic test data but timed
    // out on a real email (confirmed via a live extension submission).
    timeout: 30_000
  });

  // Confirmed real shape (from a live successful call): { message_id,
  // from_address, from_domain, return_path_address, reply_to_address,
  // spf_result, dkim_result, dmarc_result, relay_path, anomaly_flags,
  // spoofing_risk_score, risk_band, confidence, score_reasons,
  // module_status, processing_errors, processed_at }
  return data;
}

/**
 * generateFiveStageReport(caseDoc, { format })
 *
 * The report spans all three microservices' output plus confirmation, so
 * the backend assembles the full payload here and asks the forensics
 * service (which already owns PDF-rendering for the header analysis) to
 * render it — rather than duplicating a PDF renderer in Node.
 *
 * Stage order matches Case.timeline: submitted -> detection -> forensics
 * -> enrichment -> confirmed.
 */
async function generateFiveStageReport(caseDoc, { format = 'pdf' } = {}) {
  const payload = {
    caseId: caseDoc._id.toString(),
    format,
    stages: {
      submission: { sender: caseDoc.sender, subject: caseDoc.subject, at: caseDoc.createdAt },
      detection: caseDoc.detection,
      forensics: caseDoc.forensics,
      enrichment: caseDoc.enrichment,
      confirmation: {
        confirmedBy: caseDoc.confirmed_by,
        confirmedAt: caseDoc.confirmed_at,
        blockchainHash: caseDoc.blockchain_hash,
        blockchainTxId: caseDoc.blockchain_tx_id,
        anchoredAt: caseDoc.anchored_at
      }
    },
    timeline: caseDoc.timeline
  };

  const { data } = await axios.post(`${BASE_URL}/report`, payload, { timeout: 20_000 });
  // Expected shape: { reportRef, generatedAt }
  return { reportRef: data.reportRef, generatedAt: new Date(data.generatedAt) };
}

module.exports = { analyzeHeaders, generateFiveStageReport };