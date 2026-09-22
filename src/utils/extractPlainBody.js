const { simpleParser } = require('mailparser');

/**
 * stripHtml(html)
 * Minimal fallback for HTML-only emails with no text/plain MIME part.
 * Not a real HTML-to-text engine — just enough to keep obvious markup and
 * entities out of the model's input. Good enough for detection's purpose;
 * not meant to preserve layout/links.
 */
function stripHtml(html) {
  return html
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * extractPlainBody(rawEmail)
 *
 * rawEmail is the full raw MIME source (same string forensics parses for
 * headers/relay_path — untouched, see orchestrator.js). This exists
 * because that raw string was going into detection's `body` field
 * unmodified, which is a different, noisier input than anything the model
 * was trained/tested on (clean subject+body text) — confirmed as the
 * likely cause of the Indeed-email confidence mismatch (74% legitimate on
 * clean text via direct /classify testing vs ~92% phishing through the
 * real pipeline).
 *
 * Prefers the text/plain MIME part; falls back to a stripped text/html
 * part if that's all the email has; falls back to the raw string itself
 * ONLY if parsing fails outright, so detection still gets *something*
 * rather than an empty body — worse input, but not a broken pipeline.
 */
async function extractPlainBody(rawEmail) {
  if (!rawEmail) return '';

  try {
    const parsed = await simpleParser(rawEmail);

    if (parsed.text && parsed.text.trim()) return parsed.text.trim();
    if (parsed.html) return stripHtml(parsed.html);

    return ''; // parsed cleanly but genuinely no body content
  } catch (err) {
    console.error('[extractPlainBody] MIME parse failed, falling back to raw string:', err.message);
    return rawEmail;
  }
}

module.exports = { extractPlainBody, stripHtml };