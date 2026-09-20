// const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

const Case = require('../models/Case');
const { verifyJWT, requireRole } = require('../middleware/auth');
const orchestrator = require('../services/orchestrator');
const detectionService = require('../services/detectionService');
const reportService = require('../services/reportService');
const { computeRiskScore, bandFor } = require('../utils/redactCaseResponse');

// Maps the frontend's risk-severity vocabulary onto our existing risk-band
// labels (same bands the reporter-facing redacted response uses). This
// mapping is an ASSUMPTION, not a confirmed contract with the frontend —
// CRITICAL/HIGH/MEDIUM/LOW were never part of the original spec. Confirm
// with the frontend team and adjust here if their intended meaning differs.
const RISK_ALIAS_TO_LABEL = {
  CRITICAL: 'Confirmed Threat Pattern',
  HIGH: 'High Risk',
  MEDIUM: 'Suspicious',
  LOW: 'Likely Safe'
};

// Maps the frontend's status=open (not a real value in our status enum) to
// the set of statuses that aren't yet resolved one way or the other. Also
// an assumption — confirm the intended meaning of "open" with the frontend
// team if this doesn't match what they expect.
const OPEN_STATUSES = ['pending', 'analyzing', 'investigating'];

// All case routes require authentication; analysts can view/investigate,
// but confirm + report are gated to admin below via requireRole('admin').
router.use(verifyJWT);

/**
 * validateObjectId
 * Every route below takes :id and passes it straight to Mongoose's
 * findById. A malformed id (anything that isn't a 24-char hex ObjectId —
 * e.g. a frontend-generated display label like "CASE-8841" instead of the
 * real database _id) throws a CastError that, left uncaught, fails the
 * request ungracefully before any response (including CORS headers) is
 * properly sent — which shows up in the browser as a confusing "blocked by
 * CORS policy" error that has nothing to do with CORS. This middleware
 * catches that case upfront with a clear 400 instead.
 */
function validateObjectId(req, res, next) {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({
      error: 'INVALID_ID',
      message: `"${req.params.id}" is not a valid case id. Expected a 24-character database id, not a display label.`
    });
  }
  next();
}

router.use('/:id', validateObjectId);

/**
 * GET /api/cases
 * List cases. Query params: status, threatType, flagged, risk, page, limit.
 *
 * status: normal exact match against the real enum (pending/analyzing/
 * investigating/confirmed/dismissed) — EXCEPT the special value "open",
 * which expands to [pending, analyzing, investigating] (see OPEN_STATUSES
 * above). This alias is a guess at what the frontend means by "open";
 * confirm and adjust if wrong.
 *
 * risk: comma-separated list of CRITICAL/HIGH/MEDIUM/LOW (see
 * RISK_ALIAS_TO_LABEL above). Since risk isn't a stored field — it's
 * computed on the fly from detection.confidence + forensics.spoofing_risk_score,
 * same formula the reporter-facing response uses — this can't be a simple
 * Mongo query filter. Matching cases are fetched (bounded to a reasonable
 * cap) and filtered/paginated in application code instead.
 *
 * Roles: admin, analyst
 */
router.get('/', requireRole('admin', 'analyst'), async (req, res) => {
  const { status, threatType, flagged, risk, page = 1, limit = 25 } = req.query;
  const filter = {};

  if (status === 'open') {
    filter.status = { $in: OPEN_STATUSES };
  } else if (status) {
    filter.status = status;
  }
  if (threatType) filter['detection.classification'] = threatType;
  if (flagged !== undefined) filter.flagged = flagged === 'true';

  if (!risk) {
    // No risk filter — normal, efficient DB-level pagination.
    const cases = await Case.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .select('-timeline');

    const total = await Case.countDocuments(filter);
    return res.json({ data: cases, page: Number(page), limit: Number(limit), total });
  }

  // risk filter present: fetch a bounded, recent set, compute each case's
  // risk label in application code, filter, then paginate in memory. Capped
  // at 500 most-recent matches so this stays cheap even as the collection
  // grows — fine for a dashboard alert banner (small limit, recent cases),
  // not intended for deep pagination through risk-filtered history.
  const requestedLabels = risk
    .split(',')
    .map((r) => RISK_ALIAS_TO_LABEL[r.trim().toUpperCase()])
    .filter(Boolean);

  const candidates = await Case.find(filter).sort({ createdAt: -1 }).limit(500).select('-timeline');

  const matched = candidates.filter((c) => {
    const score = computeRiskScore(c.detection, c.forensics);
    const { label } = bandFor(score);
    return requestedLabels.includes(label);
  });

  const start = (page - 1) * limit;
  const pageSlice = matched.slice(start, start + Number(limit));

  res.json({ data: pageSlice, page: Number(page), limit: Number(limit), total: matched.length });
});

/**
 * GET /api/cases/:id
 * Full case document including timeline, detection/forensics/enrichment,
 * and blockchain/report audit fields.
 * Roles: admin, analyst
 */
router.get('/:id', requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const caseDoc = await Case.findById(req.params.id);
    if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });
    res.json({ data: caseDoc });
  } catch (err) {
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Could not fetch case' });
  }
});

/**
 * POST /api/cases/:id/confirm
 * NEW — marks a case as a confirmed threat and triggers the ML service's
 * blockchain-anchoring step. Admin-only: confirming a threat is the action
 * that produces an immutable, legally-relevant record, so it is
 * intentionally not available to analysts.
 *
 * Body: { notes?: string }
 */
router.post('/:id/confirm', requireRole('admin'), async (req, res) => {
  const caseDoc = await Case.findById(req.params.id);
  if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });

  if (caseDoc.status === 'confirmed') {
    return res.status(409).json({ error: 'ALREADY_CONFIRMED', message: 'Case is already confirmed' });
  }
  // Guard: don't let a case be confirmed before all three stages have run —
  // an anchored hash of an incomplete case is worse than no hash at all.
  const stagesReady =
    caseDoc.detection?.processed_at && caseDoc.forensics?.processed_at && caseDoc.enrichment?.processed_at;
  if (!stagesReady) {
    return res.status(422).json({
      error: 'INCOMPLETE_ANALYSIS',
      message: 'All three analysis stages (detection, forensics, enrichment) must complete before confirmation'
    });
  }

  try {
    const anchor = await orchestrator.confirmAndAnchor(caseDoc, {
      confirmedBy: req.user.id,
      notes: req.body.notes
    });
    res.json({ data: anchor.updatedCase });
  } catch (err) {
    console.error(`POST /cases/${req.params.id}/confirm failed:`, JSON.stringify(err?.response?.data ?? err?.message ?? err, null, 2));
    res.status(502).json({
      error: 'ANCHORING_FAILED',
      message: err?.response?.data?.detail ?? err?.response?.data?.message ?? err?.message ?? 'Anchoring failed'
    });
  }
});

/**
 * POST /api/cases/:id/report
 * REWORKED — the forensics engineer confirmed /report never existed on any
 * microservice. Report assembly now happens entirely on this backend
 * (reportService.assembleFiveStageReport) using data already stored on the
 * case document — no external service call needed. Produces structured
 * JSON, not a PDF (no PDF-generation library wired in yet).
 *
 * Admin-only: the report is the artifact that leaves the platform.
 */
router.post('/:id/report', requireRole('admin'), async (req, res) => {
  try {
    const caseDoc = await Case.findById(req.params.id);
    if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });

    const report = reportService.assembleFiveStageReport(caseDoc);
    const generatedAt = new Date();

    caseDoc.report_data = report;
    caseDoc.report_generated_by = req.user.id;
    caseDoc.report_generated_at = generatedAt;
    caseDoc.timeline.push({
      stage: 'report_generated',
      actor: req.user.id,
      summary: 'Forensic report generated',
      at: generatedAt
    });
    await caseDoc.save();

    res.json({ data: { report, generatedAt } });
  } catch (err) {
    res.status(500).json({ error: 'REPORT_GENERATION_FAILED', message: err.message });
  }
});

/**
 * POST /api/cases/:id/verify
 * NEW — on-demand tamper check against a previously anchored case. Confirmed
 * by the detection engineer: recomputes the case's hash NOW and compares it
 * to what was anchored on-chain at confirm time. Read-only — modifies
 * nothing on-chain or in our database. Available to admin AND analyst
 * (an "investigator opening a case's evidence view" was explicitly named
 * as a use case) — unlike /confirm, this carries no audit weight itself,
 * it only checks integrity of something already confirmed.
 */
router.post('/:id/verify', requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const caseDoc = await Case.findById(req.params.id);
    if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });

    if (!caseDoc.blockchain_hash) {
      return res.status(422).json({
        error: 'NOT_ANCHORED',
        message: 'This case has not been confirmed/anchored yet — nothing to verify'
      });
    }

    const caseDocument = caseDoc.toObject();
    const result = await detectionService.verifyCase(caseDoc._id.toString(), caseDocument);
    res.json({ data: result });
  } catch (err) {
    res.status(502).json({ error: 'VERIFY_FAILED', message: err.message });
  }
});

/**
 * POST /api/cases/:id/flag
 * NEW — lets an analyst (or admin) raise a case's visibility for admin
 * attention, without needing the admin-only confirm/report actions.
 * Deliberately available to BOTH roles: an admin might also want to flag
 * something urgent for a colleague, and flagging carries no legal/audit
 * weight the way confirm does — it's just a priority signal.
 *
 * Body: { flagged?: boolean (default true), reason?: string }
 * Passing { flagged: false } clears the flag (unflag) using the same route,
 * rather than needing a separate DELETE endpoint.
 */
router.post('/:id/flag', requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const caseDoc = await Case.findById(req.params.id);
    if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });

    const shouldFlag = req.body.flagged !== false; // default true unless explicitly false

    caseDoc.flagged = shouldFlag;
    caseDoc.flag_reason = shouldFlag ? req.body.reason || null : null;
    caseDoc.flagged_by = shouldFlag ? req.user.id : null;
    caseDoc.flagged_at = shouldFlag ? new Date() : null;

    caseDoc.timeline.push({
      stage: shouldFlag ? 'flagged' : 'unflagged',
      actor: req.user.id,
      summary: shouldFlag ? `Flagged for review${req.body.reason ? `: ${req.body.reason}` : ''}` : 'Flag cleared',
      at: new Date()
    });

    await caseDoc.save();
    res.json({ data: caseDoc });
  } catch (err) {
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Could not update flag' });
  }
});

module.exports = router;