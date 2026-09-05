require('dotenv').config();
const express = require('express');
const morgan = require('morgan');

const connectDB = require('./config/db');
const corsMiddleware = require('./config/cors');
const checkMicroservices = require('./config/serviceHealthCheck');

const authRoutes = require('./routes/auth.routes');
const emailsRoutes = require('./routes/emails.routes');
const casesRoutes = require('./routes/cases.routes');
const reportersRoutes = require('./routes/reporters.routes');

const app = express();

connectDB();

app.use(corsMiddleware);
app.use(express.json({ limit: '5mb' })); // raw .eml payloads can be a few hundred KB
app.use(morgan('dev'));

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'SIH26106-backend' }));

/**
 * GET /api/ping
 * Public, unauthenticated. The extension calls this once when it loads so
 * the backend can log a live confirmation of a real connection — unlike
 * the microservices/MongoDB, there's no persistent link to check for the
 * extension, so this is the closest equivalent: "did a client from the
 * expected origin actually reach us."
 */
app.get('/api/ping', (req, res) => {
  console.log(`🔌 Ping received from origin: ${req.headers.origin || 'unknown (no Origin header)'}`);
  res.json({ status: 'ok', receivedFrom: req.headers.origin || null });
});

app.use('/api/auth', authRoutes);
app.use('/api/emails', emailsRoutes);
app.use('/api/cases', casesRoutes);
app.use('/api/reporters', reportersRoutes);

// CORS rejection surfaces as a generic Error from the cors() origin callback —
// catch it here so the extension gets a clean 403 instead of a stack trace.
app.use((err, req, res, next) => {
  if (err && err.message === 'CORS blocked') {
    return res.status(403).json({ error: 'CORS_BLOCKED', message: 'Origin not allowed' });
  }
  console.error(err);
  res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`SIH26106 backend listening on :${PORT}`);
  await checkMicroservices();
});

module.exports = app;