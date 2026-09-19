const express = require('express');
const router = express.Router();

const { verifyJWT, requireRole } = require('../middleware/auth');
const detectionService = require('../services/detectionService');
const forensicsService = require('../services/forensicsService');
const enrichmentService = require('../services/enrichmentService');

// Same realistic sample used throughout manual testing earlier — has real
// headers (Return-Path, Received, Message-ID) so forensics has something
// genuine to parse rather than erroring on missing headers.
const SAMPLE_RAW_EMAIL =
  'Return-Path: <security-alert@fake-bank.example>\r\n' +
  'Received: from mail.fake-bank.example (mail.fake-bank.example [203.0.113.42])\r\n' +
  '\tby mx.recipient-domain.com with ESMTP id abc123;\r\n' +
  '\tSat, 29 Aug 2026 20:14:40 +0000\r\n' +
  'Message-ID: <20260829201440.ABC123@fake-bank.example>\r\n' +
  'From: "Fake Bank Security" <security-alert@fake-bank.example>\r\n' +
  'To: victim@recipient-domain.com\r\n' +
  'Subject: Urgent: Verify your account now\r\n' +
  'Date: Sat, 29 Aug 2026 20:14:40 +0000\r\n' +
  'Content-Type: text/plain; charset="UTF-8"\r\n' +
  'MIME-Version: 1.0\r\n\r\n' +
  'Dear Customer,\r\n\r\nWe have detected unusual activity on your account. Click here to verify.\r\n';

const SAMPLE_SENDER = 'security-alert@fake-bank.example';
const SAMPLE_SUBJECT = 'Urgent: Verify your account now';
// A real, routable IP — used to test enrichment independently, without
// needing forensics to succeed first and derive one from relay_path.
const SAMPLE_REAL_IP = '8.8.8.8';

/**
 * GET /api/debug/services
 * Admin-only. Calls detection, forensics, and enrichment DIRECTLY and
 * independently (not through the orchestrator, not creating a real Case)
 * with fixed, known-good sample data. Reports per-service success/failure
 * with timing and the real error detail — so you can tell in ONE request
 * which of the three is actually broken, instead of submitting a full case
 * and reverse-engineering it from timeline gaps.
 */
router.get('/services', verifyJWT, requireRole('admin'), async (req, res) => {
  const results = {};

  const timed = async (fn) => {
    const start = Date.now();
    const data = await fn();
    return { status: 'ok', duration_ms: Date.now() - start, response: data };
  };

  const [detectionResult, forensicsResult, enrichmentResult] = await Promise.allSettled([
    timed(() => detectionService.analyze({ sender: SAMPLE_SENDER, subject: SAMPLE_SUBJECT, rawEmail: SAMPLE_RAW_EMAIL })),
    timed(() => forensicsService.analyzeHeaders({ sender: SAMPLE_SENDER, _id: null }, SAMPLE_RAW_EMAIL, null)),
    timed(() => enrichmentService.enrich({ sender: SAMPLE_SENDER, _id: 'debug-test' }, SAMPLE_REAL_IP))
  ]);

  const formatResult = (settled) => {
    if (settled.status === 'fulfilled') return settled.value;
    const err = settled.reason;
    return {
      status: 'error',
      message: err?.response?.data ?? err?.message ?? String(err),
      http_status: err?.response?.status ?? null
    };
  };

  results.detection = formatResult(detectionResult);
  results.forensics = formatResult(forensicsResult);
  results.enrichment = formatResult(enrichmentResult);

  const allOk = Object.values(results).every((r) => r.status === 'ok');

  res.json({ data: results, summary: allOk ? 'All three services responded successfully' : 'One or more services failed — see detail above' });
});

module.exports = router;