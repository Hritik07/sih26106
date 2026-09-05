const cors = require('cors');

// FRONTEND_URL: the Vercel-deployed dashboard/report UI (fixed, always allowlisted exactly).
// LOCAL_FRONTEND_URL: optional, for local frontend dev (e.g. Vite's default
// http://localhost:5173) — only set this in your own .env, never commit a
// real one, since it's meant to vary per developer's local setup.
// EXTENSION_ORIGIN: chrome-extension://<packed-extension-id> — optional, exact-match
// allowlist entry, useful once you have a published/fixed extension ID.
//
// ALLOW_ANY_EXTENSION_ORIGIN=true (set in .env during development only): any
// chrome-extension:// origin is accepted, not just EXTENSION_ORIGIN. This exists
// because unpacked dev-mode extensions get a random ID that changes across
// machines/reinstalls — but it still only opens the door to Chrome extension
// origins specifically, never to arbitrary websites the way `origin: true`
// (reflecting every origin) would. Turn this off for production by leaving
// the env var unset — then only the exact EXTENSION_ORIGIN is trusted.
const allowedOrigins = [process.env.FRONTEND_URL, process.env.LOCAL_FRONTEND_URL, process.env.EXTENSION_ORIGIN].filter(
  Boolean
);
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