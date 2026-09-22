const crypto = require('crypto');
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY); // same Resend account otpService.js already uses
const RESET_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes — longer than the 5min OTP window, since this is a link a person has to go open their email for, not a code they're actively watching for

function generateToken() {
  // 32 random bytes -> 64 hex chars. This is a bearer credential (whoever
  // has it can set the account's password), so it needs real entropy —
  // unlike a 6-digit OTP, there's no separate userId + attempt-counter
  // narrowing the search space here.
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * issuePasswordReset(user)
 * Generates a token, stores its hash + expiry on the user doc (mutates in
 * place — caller is responsible for .save()), and emails a reset link.
 * The raw token is never persisted or logged — only its hash is stored,
 * same pattern as otpService's OTP codes.
 */
async function issuePasswordReset(user) {
  const token = generateToken();

  user.resetPasswordTokenHash = hashToken(token);
  user.resetPasswordExpiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

  // PASSWORD_RESET_URL e.g. 'https://your-frontend.example.com/reset-password'
  // Falls back to emailing the raw token alone if that env var isn't set,
  // so this doesn't hard-fail in an environment where the frontend URL
  // hasn't been configured yet.
  const resetUrl = process.env.PASSWORD_RESET_URL
    ? `${process.env.PASSWORD_RESET_URL}?token=${token}`
    : null;

  await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: 'Reset your password',
    text: resetUrl
      ? `Reset your password: ${resetUrl}\nThis link expires in 30 minutes. If you didn't request this, ignore this email.`
      : `Your password reset code is ${token}. It expires in 30 minutes. If you didn't request this, ignore this email.`
  });

  return token; // returned only for local/dev logging by the caller if needed — never sent back in the API response
}

/**
 * clearPasswordReset(user) — call after a successful reset so the token can't be reused.
 */
function clearPasswordReset(user) {
  user.resetPasswordTokenHash = null;
  user.resetPasswordExpiresAt = null;
}

module.exports = { hashToken, issuePasswordReset, clearPasswordReset };