const jwt = require('jsonwebtoken');

/**
 * verifyJWT
 * Verifies the bearer token and attaches { id, role, email } to req.user.
 * Role is trusted from the token payload — it must have been set at login
 * time by auth.routes.js from the User document, never from client input.
 */
function verifyJWT(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Missing bearer token' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Invalid or expired token' });
  }
}

/**
 * requireRole(...roles)
 * Use after verifyJWT. Rejects with 403 if req.user.role is not in the
 * allowed list. Usage:
 *   router.post('/:id/confirm', verifyJWT, requireRole('admin'), handler)
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'No authenticated user on request' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: `This action requires one of: ${allowedRoles.join(', ')}`
      });
    }
    return next();
  };
}

module.exports = { verifyJWT, requireRole };