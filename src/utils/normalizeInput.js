/**
 * normalizeInput(rawEmail)
 *
 * Does the cheap, shared parsing every downstream consumer needs (backend
 * validation, detection's quick /analyze path, Email.parsedHeaders) so
 * that logic lives in exactly one place instead of being re-implemented in
 * each route. Deliberately lightweight — it is NOT the SPF/DKIM/DMARC
 * parser; that stays in the forensics microservice, which needs the full
 * header set and does real signature validation.
 */
function normalizeInput(rawEmail) {
  const headerBlock = rawEmail.split(/\r?\n\r?\n/)[0] || '';
  const headers = {};

  headerBlock.split(/\r?\n/).forEach((line) => {
    const match = line.match(/^([A-Za-z-]+):\s*(.*)$/);
    if (match) headers[match[1].toLowerCase()] = match[2].trim();
  });

  const fromHeader = headers['from'] || '';
  const emailMatch = fromHeader.match(/[\w.+-]+@[\w-]+\.[\w.-]+/);

  return {
    headers,
    sender: emailMatch ? emailMatch[0].toLowerCase() : undefined,
    subject: headers['subject'] || undefined
  };
}

module.exports = normalizeInput;