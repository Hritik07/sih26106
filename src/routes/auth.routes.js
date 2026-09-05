const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const router = express.Router();
const User = require('../models/User');
const { validate } = require('../middleware/validate');
const { verifyJWT, requireRole } = require('../middleware/auth');

/**
 * POST /api/auth/login
 * Public. Issues a JWT with role taken from the User document — the
 * client never gets to assert its own role.
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

    const token = jwt.sign({ sub: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '8h'
    });

    res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
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

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), passwordHash, role, name });

    res.status(201).json({ data: { id: user._id, email: user.email, role: user.role } });
  }
);

module.exports = router;