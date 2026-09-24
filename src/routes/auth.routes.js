// const express = require('express');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');

// const router = express.Router();
// const User = require('../models/User');
// const { validate } = require('../middleware/validate');
// const { verifyJWT, requireRole } = require('../middleware/auth');
// const otpService = require('../services/otpService');
// const passwordResetService = require('../services/passwordResetService');

// function signSession(user) {
//   return jwt.sign({ sub: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
//     expiresIn: process.env.JWT_EXPIRES_IN || '8h'
//   });
// }

// /**
//  * POST /api/auth/login
//  * Public. Password is checked first, unconditionally, exactly as before —
//  * a wrong password always fails right here, before either branch below is
//  * even reached, so neither branch can be used to probe whether an account
//  * has mustChangePassword set.
//  *
//  * On a correct password, branches instead of issuing a token immediately:
//  *   - mustChangePassword === true  -> no OTP sent, no token issued. The
//  *     client must call /set-initial-password next.
//  *   - mustChangePassword === false -> an OTP is emailed (2FA), no token
//  *     issued yet either. The client must call /verify-otp next.
//  * A JWT is now NEVER issued directly from /login for staff accounts.
//  */
// router.post(
//   '/login',
//   validate({ email: { required: true, type: 'string' }, password: { required: true, type: 'string' } }),
//   async (req, res) => {
//     const { email, password } = req.body;
//     const user = await User.findOne({ email: email.toLowerCase() });
//     if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });

//     const match = await bcrypt.compare(password, user.passwordHash);
//     if (!match) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });

//     if (user.mustChangePassword) {
//       return res.json({
//         data: { userId: user._id, requiresPasswordChange: true, message: 'Set a new password to continue.' }
//       });
//     }

//     await otpService.issueOtp(user, 'login');
//     await user.save();

//     res.json({ data: { userId: user._id, mfaRequired: true, message: 'OTP sent to your email' } });
//   }
// );

// /**
//  * POST /api/auth/set-initial-password
//  * Only reachable for an account with mustChangePassword still true.
//  * Re-verifies the CURRENT (temp) password rather than trusting a bare
//  * userId — same reasoning as /login: identity is proven by a password
//  * match, not by knowing an id. On success, this is the one transaction
//  * that skips OTP entirely and issues a session directly, since the user
//  * just proved both "knows the temp password" and "set a new one" in the
//  * same request; every login after this one goes through /login -> 2FA.
//  */
// router.post(
//   '/set-initial-password',
//   validate({
//     userId: { required: true, type: 'string' },
//     tempPassword: { required: true, type: 'string' },
//     newPassword: { required: true, type: 'string' }
//   }),
//   async (req, res) => {
//     const { userId, tempPassword, newPassword } = req.body;
//     const user = await User.findById(userId);
//     if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });

//     if (!user.mustChangePassword) {
//       return res
//         .status(409)
//         .json({ error: 'ALREADY_SET', message: 'A password has already been set for this account — use /login.' });
//     }

//     const match = await bcrypt.compare(tempPassword, user.passwordHash);
//     if (!match) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });

//     user.passwordHash = await bcrypt.hash(newPassword, 10);
//     user.mustChangePassword = false;
//     await user.save();

//     const token = signSession(user);
//     res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
//   }
// );

// /**
//  * POST /api/auth/verify-otp
//  * Second step of every login after the first. Mirrors
//  * reporters.routes.js's /verify-otp almost exactly — same otpService
//  * calls, same attempt-counting/error-reason shape — just against User
//  * instead of Reporter, and issuing a staff session token on success.
//  */
// router.post(
//   '/verify-otp',
//   validate({ userId: { required: true, type: 'string' }, otp: { required: true, type: 'string' } }),
//   async (req, res) => {
//     const user = await User.findById(req.body.userId);
//     if (!user) return res.status(404).json({ error: 'NOT_FOUND', message: 'User not found' });

//     const result = otpService.verifyOtp(user, req.body.otp);

//     if (!result.ok) {
//       if (result.reason === 'INCORRECT') {
//         user.otpAttempts += 1;
//         await user.save();
//       }
//       const messages = {
//         NO_ACTIVE_OTP: 'No OTP request is active — log in again to request a new code.',
//         TOO_MANY_ATTEMPTS: 'Too many incorrect attempts — log in again to request a new code.',
//         EXPIRED: 'This code has expired — log in again to request a new code.',
//         INCORRECT: 'Incorrect code.'
//       };
//       return res.status(400).json({ error: result.reason, message: messages[result.reason] });
//     }

//     otpService.clearOtp(user);
//     await user.save();

//     const token = signSession(user);
//     res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
//   }
// );

// /**
//  * POST /api/auth/forgot-password
//  * Public. Always returns the same generic response whether or not the
//  * email matches an account — this endpoint must not be usable to check
//  * which emails are registered. Real work only happens inside the `if`.
//  */
// router.post('/forgot-password', validate({ email: { required: true, type: 'string' } }), async (req, res) => {
//   const user = await User.findOne({ email: req.body.email.toLowerCase() });

//   if (user) {
//     await passwordResetService.issuePasswordReset(user);
//     await user.save();
//   }

//   res.json({ data: { message: 'If that email is registered, a password reset link has been sent.' } });
// });

// /**
//  * POST /api/auth/reset-password
//  * Public. Looked up by the TOKEN's hash, not by email/userId — the reset
//  * link only carries the token, so that's the only thing this has to go on.
//  * A valid, unexpired token is sufficient proof of identity here (the same
//  * trust level a "reset your password" email link always carries) — unlike
//  * /set-initial-password, there's no separate current-password check,
//  * because the whole point of this flow is that the user has forgotten it.
//  *
//  * Does NOT auto-issue a session on success. The user goes back through the
//  * normal /login flow afterward — which, since mustChangePassword is left
//  * untouched by this route (not forced true or false), means: if this was
//  * already a fully set-up account, they land straight on 2FA as usual.
//  */
// router.post(
//   '/reset-password',
//   validate({ token: { required: true, type: 'string' }, newPassword: { required: true, type: 'string' } }),
//   async (req, res) => {
//     const { token, newPassword } = req.body;
//     const tokenHash = passwordResetService.hashToken(token);

//     const user = await User.findOne({
//       resetPasswordTokenHash: tokenHash,
//       resetPasswordExpiresAt: { $gt: new Date() }
//     });

//     if (!user) {
//       return res
//         .status(400)
//         .json({ error: 'INVALID_OR_EXPIRED_TOKEN', message: 'This reset link is invalid or has expired.' });
//     }

//     user.passwordHash = await bcrypt.hash(newPassword, 10);
//     passwordResetService.clearPasswordReset(user);
//     await user.save();

//     res.json({ data: { message: 'Password has been reset. You can now log in.' } });
//   }
// );

// /**
//  * POST /api/auth/register
//  * Admin-only. Only an existing admin can create new accounts (including
//  * other admins) — there is no public self-registration, since role
//  * (analyst vs admin) determines access to confirm/report.
//  */
// router.post(
//   '/register',
//   verifyJWT,
//   requireRole('admin'),
//   validate({
//     email: { required: true, type: 'string' },
//     password: { required: true, type: 'string' },
//     role: { required: true, type: 'string', enum: ['admin', 'analyst'] }
//   }),
//   async (req, res) => {
//     const { email, password, role, name } = req.body;

//     const existing = await User.findOne({ email: email.toLowerCase() });
//     if (existing) return res.status(409).json({ error: 'EMAIL_IN_USE', message: 'Email already registered' });

//     // The password set here by the admin is a TEMP password only — the new
//     // user is forced through /set-initial-password on their first login.
//     // mustChangePassword isn't set explicitly; it relies on the schema
//     // default (true), which is what actually triggers that first-login flow.
//     const passwordHash = await bcrypt.hash(password, 10);
//     const user = await User.create({ email: email.toLowerCase(), passwordHash, role, name });

//     res.status(201).json({ data: { id: user._id, email: user.email, role: user.role } });
//   }
// );

// module.exports = router;


// V2 //



const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const router = express.Router();
const User = require('../models/User');
const { validate } = require('../middleware/validate');
const { verifyJWT, requireRole } = require('../middleware/auth');
const otpService = require('../services/otpService');
const passwordResetService = require('../services/passwordResetService');

function signSession(user) {
  return jwt.sign({ sub: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '8h'
  });
}

/**
 * POST /api/auth/login
 * Public. Password is checked first, unconditionally, exactly as before —
 * a wrong password always fails right here, before either branch below is
 * even reached, so neither branch can be used to probe whether an account
 * has mustChangePassword set.
 *
 * On a correct password, branches instead of issuing a token immediately:
 *   - mustChangePassword === true  -> no OTP sent, no token issued. The
 *     client must call /set-initial-password next.
 *   - mustChangePassword === false -> an OTP is emailed (2FA), no token
 *     issued yet either. The client must call /verify-otp next.
 * A JWT is now NEVER issued directly from /login for staff accounts.
 */
router.post(
  '/login',
  validate({ email: { required: true, type: 'string' }, password: { required: true, type: 'string' } }),
  async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });

    if (user.mustChangePassword) {
      return res.json({
        data: { userId: user._id, requiresPasswordChange: true, message: 'Set a new password to continue.' }
      });
    }

    await otpService.issueOtp(user, 'login');
    await user.save();

    res.json({ data: { userId: user._id, mfaRequired: true, message: 'OTP sent to your email' } });
  }
);

/**
 * POST /api/auth/set-initial-password
 * Only reachable for an account with mustChangePassword still true.
 * Re-verifies the CURRENT (temp) password rather than trusting a bare
 * userId — same reasoning as /login: identity is proven by a password
 * match, not by knowing an id. On success, this is the one transaction
 * that skips OTP entirely and issues a session directly, since the user
 * just proved both "knows the temp password" and "set a new one" in the
 * same request; every login after this one goes through /login -> 2FA.
 */
router.post(
  '/set-initial-password',
  validate({
    userId: { required: true, type: 'string' },
    tempPassword: { required: true, type: 'string' },
    newPassword: { required: true, type: 'string' }
  }),
  async (req, res) => {
    const { userId, tempPassword, newPassword } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });

    if (!user.mustChangePassword) {
      return res
        .status(409)
        .json({ error: 'ALREADY_SET', message: 'A password has already been set for this account — use /login.' });
    }

    const match = await bcrypt.compare(tempPassword, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.mustChangePassword = false;
    await user.save();

    const token = signSession(user);
    res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  }
);

/**
 * POST /api/auth/verify-otp
 * Second step of every login after the first. Mirrors
 * reporters.routes.js's /verify-otp almost exactly — same otpService
 * calls, same attempt-counting/error-reason shape — just against User
 * instead of Reporter, and issuing a staff session token on success.
 */
router.post(
  '/verify-otp',
  validate({ userId: { required: true, type: 'string' }, otp: { required: true, type: 'string' } }),
  async (req, res) => {
    const user = await User.findById(req.body.userId);
    if (!user) return res.status(404).json({ error: 'NOT_FOUND', message: 'User not found' });

    const result = otpService.verifyOtp(user, req.body.otp);

    if (!result.ok) {
      if (result.reason === 'INCORRECT') {
        user.otpAttempts += 1;
        await user.save();
      }
      const messages = {
        NO_ACTIVE_OTP: 'No OTP request is active — log in again to request a new code.',
        TOO_MANY_ATTEMPTS: 'Too many incorrect attempts — log in again to request a new code.',
        EXPIRED: 'This code has expired — log in again to request a new code.',
        INCORRECT: 'Incorrect code.'
      };
      return res.status(400).json({ error: result.reason, message: messages[result.reason] });
    }

    otpService.clearOtp(user);
    await user.save();

    const token = signSession(user);
    res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  }
);

/**
 * POST /api/auth/forgot-password
 * Public. Always returns the same generic response whether or not the
 * email matches an account — this endpoint must not be usable to check
 * which emails are registered. Real work only happens inside the `if`.
 */
router.post('/forgot-password', validate({ email: { required: true, type: 'string' } }), async (req, res) => {
  const user = await User.findOne({ email: req.body.email.toLowerCase() });

  if (user) {
    await passwordResetService.issuePasswordReset(user);
    await user.save();
  }

  res.json({ data: { message: 'If that email is registered, a password reset link has been sent.' } });
});

/**
 * POST /api/auth/reset-password
 * Public. Looked up by the TOKEN's hash, not by email/userId — the reset
 * link only carries the token, so that's the only thing this has to go on.
 * A valid, unexpired token is sufficient proof of identity here (the same
 * trust level a "reset your password" email link always carries) — unlike
 * /set-initial-password, there's no separate current-password check,
 * because the whole point of this flow is that the user has forgotten it.
 *
 * Does NOT auto-issue a session on success. The user goes back through the
 * normal /login flow afterward — which, since mustChangePassword is left
 * untouched by this route (not forced true or false), means: if this was
 * already a fully set-up account, they land straight on 2FA as usual.
 */
router.post(
  '/reset-password',
  validate({ token: { required: true, type: 'string' }, newPassword: { required: true, type: 'string' } }),
  async (req, res) => {
    const { token, newPassword } = req.body;
    const tokenHash = passwordResetService.hashToken(token);

    const user = await User.findOne({
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpiresAt: { $gt: new Date() }
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: 'INVALID_OR_EXPIRED_TOKEN', message: 'This reset link is invalid or has expired.' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    passwordResetService.clearPasswordReset(user);
    await user.save();

    res.json({ data: { message: 'Password has been reset. You can now log in.' } });
  }
);

/**
 * POST /api/auth/register
 * Admin-only. Only an existing admin can create new accounts (including
 * other admins) — there is no public self-registration, since role
 * (analyst vs admin) determines access to confirm/report.
 */
router.post(
  '/register',
  verifyJWT,
  requireRole('admin'),
  validate({
    email: { required: true, type: 'string' },
    password: { required: true, type: 'string' },
    role: { required: true, type: 'string', enum: ['admin', 'analyst'] }
  }),
  async (req, res) => {
    const { email, password, role, name } = req.body;

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'EMAIL_IN_USE', message: 'Email already registered' });

    // The password set here by the admin is a TEMP password only — the new
    // user is forced through /set-initial-password on their first login.
    // mustChangePassword isn't set explicitly; it relies on the schema
    // default (true), which is what actually triggers that first-login flow.
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash, role, name });

    res.status(201).json({ data: { id: user._id, email: user.email, role: user.role } });
  }
);

/**
 * GET /api/auth/analysts
 * Admin-only. Backs the case detail page's "Assign analyst" dropdown,
 * which was previously hardcoded mock data on the frontend with no real
 * endpoint behind it. Returns only role:'analyst' accounts — deliberately
 * NOT admins, to match what that dropdown is actually for. If assigning a
 * case to an admin is also meant to be possible, that's a separate,
 * intentional decision to widen this query, not an oversight here.
 * Only the fields the dropdown needs — never passwordHash, OTP fields, or
 * reset-token fields.
 */
router.get('/analysts', verifyJWT, requireRole('admin'), async (req, res) => {
  const analysts = await User.find({ role: 'analyst' }).select('_id name email').sort({ name: 1 });
  res.json({ data: analysts.map((a) => ({ id: a._id, name: a.name, email: a.email })) });
});

module.exports = router;