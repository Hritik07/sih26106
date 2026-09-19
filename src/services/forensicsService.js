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

  // CONFIRMED real shape (grepped from forensics' actual source code —
  // corrected from earlier guesses): { message_id, from_address,
  // from_domain, return_path_address, reply_to_address, spf_result: {result,
  // checked_domain, checked_ip, explanation}, dkim_result: {result, ...},
  // dmarc_result: {result, policy, explanation}, relay_path: {hop_count,
  // hops: [...]}, earliest_trustworthy_ip, anomaly_flags: [{code, severity,
  // weight, description}], spoofing_risk_score, risk_tier, score_reasons,
  // processing_errors, processed_at }. NOTE: `.status` fields are actually
  // `.result`, there is no `confidence` or `module_status` field, and
  // `risk_band` is actually `risk_tier` — all corrected in Case.js's schema.
  return data;
}

module.exports = { analyzeHeaders };