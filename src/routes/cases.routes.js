const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

const Case = require('../models/Case');
const { verifyJWT, requireRole } = require('../middleware/auth');
const orchestrator = require('../services/orchestrator');
const forensicsService = require('../services/forensicsService');

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
 * List cases. Query params: status, threatType, page, limit.
 * Roles: admin, analyst
 */
router.get('/', requireRole('admin', 'analyst'), async (req, res) => {
  const { status, threatType, flagged, page = 1, limit = 25 } = req.query;
  const filter = {};
  if (status) filter.status = status;
  if (threatType) filter['detection.threatType'] = threatType;
  if (flagged !== undefined) filter.flagged = flagged === 'true';

  const cases = await Case.find(filter)
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(Number(limit))
    .select('-timeline'); // list view omits the full timeline for payload size

  const total = await Case.countDocuments(filter);
  res.json({ data: cases, page: Number(page), limit: Number(limit), total });
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
    res.status(502).json({ error: 'ANCHORING_FAILED', message: err.message });
  }
});

/**
 * POST /api/cases/:id/report
 * UPDATED — previously any authenticated analyst could generate/export a
 * report; now admin-only, since the report is the artifact that leaves the
 * platform (shared externally / used as evidence).
 *
 * Body: { format?: 'pdf' | 'json' } (default 'pdf')
 */
router.post('/:id/report', requireRole('admin'), async (req, res) => {
  const caseDoc = await Case.findById(req.params.id);
  if (!caseDoc) return res.status(404).json({ error: 'NOT_FOUND', message: 'Case not found' });

  try {
    const { reportRef, generatedAt } = await forensicsService.generateFiveStageReport(caseDoc, {
      format: req.body.format || 'pdf'
    });

    caseDoc.reportRef = reportRef;
    caseDoc.report_generated_by = req.user.id;
    caseDoc.report_generated_at = generatedAt;
    caseDoc.timeline.push({
      stage: 'report_generated',
      actor: req.user.id,
      summary: `Forensic report generated (${req.body.format || 'pdf'})`,
      at: generatedAt
    });
    await caseDoc.save();

    res.json({ data: { reportRef, generatedAt } });
  } catch (err) {
    res.status(500).json({ error: 'REPORT_GENERATION_FAILED', message: err.message });
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