const cors = require('cors');

// FRONTEND_URL: kept for backward compatibility — the primary frontend URL.
// LOCAL_FRONTEND_URL: optional, for local frontend dev (e.g. Vite's default
// http://localhost:5173).
// ALLOWED_ORIGINS: comma-separated list of any ADDITIONAL origins to trust —
// this is what you update when the frontend gets a new custom domain, a new
// Vercel preview URL, or www/non-www variants, WITHOUT needing to guess
// which single env var slot to change. Example:
//   ALLOWED_ORIGINS=https://www.mailrakshak.tech,https://mailrakshak.tech,https://sih26106-frontend.vercel.app
// EXTENSION_ORIGIN: chrome-extension://<packed-extension-id> — optional, exact-match.
//
// ALLOW_ANY_EXTENSION_ORIGIN=true (development only): any chrome-extension://
// origin is accepted, not just EXTENSION_ORIGIN — for unpacked dev installs
// whose ID changes across machines. Never opens the door to non-extension
// origins the way `origin: true` would.
const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.LOCAL_FRONTEND_URL,
  process.env.EXTENSION_ORIGIN,
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()) : [])
].filter(Boolean);

const allowAnyExtension = process.env.ALLOW_ANY_EXTENSION_ORIGIN === 'true';

module.exports = cors({
  origin(origin, callback) {
    // requests with no Origin header (curl, server-to-server, Postman) are allowed;
    // browser-sent requests are checked against the allowlist.
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    if (allowAnyExtension && origin.startsWith('chrome-extension://')) return callback(null, true);
    return callback(new Error('CORS blocked'));
  },
  credentials: true
});
