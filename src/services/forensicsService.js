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
 * sender/caseId ride along as regular form fields.
 *
 * The `headers` parameter (our own crude regex-parsed header object from
 * normalizeInput.js) is INTENTIONALLY no longer sent — real-pipeline
 * requests that included it got back responses missing spf_result/
 * dkim_result/dmarc_result entirely, while the debug route's identical
 * test (which never sent this field) got a full response. Forensics parses
 * the raw file itself; sending our own parsed headers alongside it was
 * redundant at best. Removing it as the most concrete lead to test.
 */
async function analyzeHeaders(caseDoc, rawEmail, headers) {
  const form = new FormData();
  form.append('file', Buffer.from(rawEmail || '', 'utf-8'), {
    filename: 'email.eml',
    contentType: 'message/rfc822'
  });
  form.append('sender', caseDoc.sender || '');
  if (caseDoc._id) form.append('caseId', caseDoc._id.toString());

  const { data } = await axios.post(`${BASE_URL}/analyze-headers`, form, {
    headers: form.getHeaders(),
    // Real emails need real SPF/DKIM/DMARC DNS lookups against the actual
    // sending domain — much slower than the "none"/instant response our
    // fake test domain got. 10s was fine for synthetic test data but timed
    // out on a real email (confirmed via a live extension submission).
    timeout: 30_000
  });

  // Response shape has been observed to vary across calls — see the
  // multiple field-name fallbacks in orchestrator.js's readSpfStatus/
  // readDkimStatus/readDmarcStatus/deriveOriginIp rather than trusting one
  // fixed shape here.
  return data;
}

module.exports = { analyzeHeaders };