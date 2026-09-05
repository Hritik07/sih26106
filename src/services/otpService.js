const crypto = require('crypto');
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
const OTP_MAX_ATTEMPTS = 5;

function generateOtp() {
  // 6-digit numeric code, zero-padded
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function hashOtp(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

/**
 * issueOtp(reporter, purpose)
 * Generates a code, stores its hash + expiry on the reporter doc (mutates
 * in place — caller is responsible for .save()), and emails it via Resend.
 * The plaintext code is never persisted or logged.
 */
async function issueOtp(reporter, purpose) {
  const code = generateOtp();

  reporter.otpHash = hashOtp(code);
  reporter.otpExpiresAt = new Date(Date.now() + OTP_TTL_MS);
  reporter.otpPurpose = purpose;
  reporter.otpAttempts = 0;

  await resend.emails.send({
    from: process.env.EMAIL_FROM, // e.g. 'SIH26106 Reporting <noreply@yourdomain.com>'
    to: reporter.email,
    subject: 'Your verification code',
    text: `Your verification code is ${code}. It expires in 5 minutes. If you didn't request this, ignore this email.`
  });

  return code; // returned only for local/dev logging by the caller if needed — never sent back in the API response
}

/**
 * verifyOtp(reporter, submittedCode)
 * Returns { ok: true } or { ok: false, reason } without throwing, so the
 * route can turn `reason` into the right HTTP status/message.
 */
function verifyOtp(reporter, submittedCode) {
  if (!reporter.otpHash || !reporter.otpExpiresAt) {
    return { ok: false, reason: 'NO_ACTIVE_OTP' };
  }
  if (reporter.otpAttempts >= OTP_MAX_ATTEMPTS) {
    return { ok: false, reason: 'TOO_MANY_ATTEMPTS' };
  }
  if (reporter.otpExpiresAt < new Date()) {
    return { ok: false, reason: 'EXPIRED' };
  }
  if (hashOtp(submittedCode) !== reporter.otpHash) {
    return { ok: false, reason: 'INCORRECT' };
  }
  return { ok: true };
}

/**
 * clearOtp(reporter) — call after a successful verify so the code can't be reused.
 */
function clearOtp(reporter) {
  reporter.otpHash = null;
  reporter.otpExpiresAt = null;
  reporter.otpPurpose = null;
  reporter.otpAttempts = 0;
}

module.exports = { issueOtp, verifyOtp, clearOtp };