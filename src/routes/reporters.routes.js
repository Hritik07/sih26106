const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();
const Reporter = require('../models/Reporter');
const Case = require('../models/Case');
const { validate } = require('../middleware/validate');
const { verifyJWT, requireRole } = require('../middleware/auth');
const otpService = require('../services/otpService');
const { buildReporterResponse } = require('../utils/redactCaseResponse');

/**
 * POST /api/reporters/signup
 * Creates (or re-uses, if unverified) a reporter record and emails an OTP.
 * No password is ever set — email OTP is the only credential, for every
 * login going forward too.
 */
router.post(
  '/signup',
  validate({
    name: { required: true, type: 'string' },
    phone: { required: true, type: 'string' },
    email: { required: true, type: 'string' }
  }),
  async (req, res) => {
    const { name, phone, email, organization } = req.body;
    const normalizedEmail = email.toLowerCase();

    let reporter = await Reporter.findOne({ email: normalizedEmail });

    if (reporter && reporter.email_verified) {
      return res
        .status(409)
        .json({ error: 'ALREADY_REGISTERED', message: 'This email is already registered — use /login instead.' });
    }

    if (!reporter) {
      reporter = new Reporter({ name, email: normalizedEmail, phone, organization });
    } else {
      // unverified record from an abandoned signup — refresh details and re-send
      reporter.name = name;
      reporter.phone = phone;
      reporter.organization = organization;
    }

    await otpService.issueOtp(reporter, 'signup');
    await reporter.save();

    res.status(200).json({ data: { reporterId: reporter._id, message: 'OTP sent to your email' } });
  }
);

/**
 * POST /api/reporters/login
 * Looks up by email or phone, emails an OTP to the account's email either way
 * (phone is not itself a delivery channel now that OTP is email-based).
 */
router.post('/login', validate({ email: { type: 'string' }, phone: { type: 'string' } }), async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) {
    return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'email or phone is required' });
  }

  const reporter = email
    ? await Reporter.findOne({ email: email.toLowerCase() })
    : await Reporter.findOne({ phone });

  if (!reporter) {
    return res.status(404).json({ error: 'NOT_FOUND', message: 'No reporter account found' });
  }

  await otpService.issueOtp(reporter, 'login');
  await reporter.save();

  res.status(200).json({ data: { reporterId: reporter._id, message: 'OTP sent to your email' } });
});

/**
 * POST /api/reporters/verify-otp
 * Verifies the code, marks email_verified on signup, issues the reporter
 * session token (role: 'reporter' — reuses the same JWT_SECRET/verifyJWT
 * pipeline as staff tokens, so downstream role checks work unmodified).
 */
router.post(
  '/verify-otp',
  validate({ reporterId: { required: true, type: 'string' }, otp: { required: true, type: 'string' } }),
  async (req, res) => {
    const reporter = await Reporter.findById(req.body.reporterId);
    if (!reporter) return res.status(404).json({ error: 'NOT_FOUND', message: 'Reporter not found' });

    const result = otpService.verifyOtp(reporter, req.body.otp);

    if (!result.ok) {
      if (result.reason === 'INCORRECT') {
        reporter.otpAttempts += 1;
        await reporter.save();
      }
      const messages = {
        NO_ACTIVE_OTP: 'No OTP request is active — request a new code.',
        TOO_MANY_ATTEMPTS: 'Too many incorrect attempts — request a new code.',
        EXPIRED: 'This code has expired — request a new code.',
        INCORRECT: 'Incorrect code.'
      };
      return res.status(400).json({ error: result.reason, message: messages[result.reason] });
    }

    reporter.email_verified = true;
    otpService.clearOtp(reporter);
    await reporter.save();

    const token = jwt.sign({ sub: reporter._id, role: 'reporter', email: reporter.email }, process.env.JWT_SECRET, {
      expiresIn: process.env.REPORTER_JWT_EXPIRES_IN || '30d'
    });

    res.json({
      data: { token, reporter: { id: reporter._id, name: reporter.name, email: reporter.email } }
    });
  }
);

/**
 * GET /api/reporters/me/cases
 * Reporter-only. Returns ONLY that reporter's own submissions, each in the
 * same redacted shape as /emails/submit — never the full case object.
 */
router.get('/me/cases', verifyJWT, requireRole('reporter'), async (req, res) => {
  const cases = await Case.find({ reporter_id: req.user.id })
    .sort({ createdAt: -1 })
    .select('detection forensics createdAt');

  const data = cases.map((c) =>
    buildReporterResponse({
      caseId: c._id,
      detection: c.detection,
      forensics: c.forensics,
      submittedAt: c.createdAt
    })
  );

  res.json({ data });
});

module.exports = router;