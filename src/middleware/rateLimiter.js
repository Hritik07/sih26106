const Case = require('../models/Case');

const DEFAULT_DAILY_LIMIT = 8; // within the 5-10/day range from the spec; tune via env

/**
 * reporterDailySubmissionLimit
 *
 * Server-side enforcement (never trust the extension/UI to self-limit).
 * Rolling 24h window, not calendar-day, per spec. Only applies to
 * req.user.role === 'reporter' — admin/analyst submissions are unaffected,
 * so mount this AFTER role is known (after verifyJWT) and only on the
 * reporter-reachable /emails/submit route.
 *
 * Counts existing Case documents rather than a separate log collection —
 * one less moving part, and Case already has reporter_id + createdAt.
 */
async function reporterDailySubmissionLimit(req, res, next) {
  if (!req.user || req.user.role !== 'reporter') return next(); // not a reporter, nothing to enforce here

  const limit = Number(process.env.REPORTER_DAILY_LIMIT || DEFAULT_DAILY_LIMIT);
  const windowStart = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const recentCases = await Case.find({
    reporter_id: req.user.id,
    createdAt: { $gte: windowStart }
  })
    .sort({ createdAt: 1 })
    .select('createdAt');

  if (recentCases.length < limit) return next();

  // Reset time = when the oldest submission inside the current window rolls
  // out of the 24h lookback, not midnight — this IS a rolling window, not a calendar day.
  const oldest = recentCases[0].createdAt;
  const resetsAt = new Date(oldest.getTime() + 24 * 60 * 60 * 1000);
  const msRemaining = resetsAt - Date.now();
  const hours = Math.floor(msRemaining / (60 * 60 * 1000));
  const minutes = Math.floor((msRemaining % (60 * 60 * 1000)) / (60 * 1000));

  return res.status(429).json({
    error: 'DAILY_LIMIT_EXCEEDED',
    message: `You've reached today's submission limit (${limit}). Resets in ${hours}h ${minutes}m.`,
    resets_at: resetsAt
  });
}

module.exports = { reporterDailySubmissionLimit };