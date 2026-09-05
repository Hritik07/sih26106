// const express = require('express');
// const router = express.Router();

// const Case = require('../models/Case');
// const Email = require('../models/Email');
// const { verifyJWT, requireRole } = require('../middleware/auth');
// const { validate } = require('../middleware/validate');
// const { reporterDailySubmissionLimit } = require('../middleware/rateLimiter');
// const normalizeInput = require('../utils/normalizeInput');
// const detectionService = require('../services/detectionService');
// const forensicsService = require('../services/forensicsService');
// const orchestrator = require('../services/orchestrator');
// const { buildReporterResponse } = require('../utils/redactCaseResponse');

// router.use(verifyJWT);

// /**
//  * POST /api/emails/analyze
//  * Staff (admin/analyst): unchanged — fast detection-only preview, no persistence.
//  * Reporter: also stays a preview (no Case is created), but runs detection +
//  * forensics headers in parallel (not enrichment — too slow for an inline
//  * check, and risk_score doesn't need it) so a real risk_score can be
//  * returned. case_id is null here since nothing is persisted yet — a
//  * reporter only gets a real case_id from /submit.
//  */
// router.post(
//   '/analyze',
//   requireRole('admin', 'analyst', 'reporter'),
//   validate({ rawEmail: { required: true, type: 'string' } }),
//   async (req, res) => {
//     const normalized = normalizeInput(req.body.rawEmail);
//     const stubCase = { sender: normalized.sender, subject: normalized.subject, rawEmail: req.body.rawEmail };

//     try {
//       if (req.user.role === 'reporter') {
//         const [detectionResult, forensicsResult] = await Promise.allSettled([
//           detectionService.analyze(stubCase),
//           forensicsService.analyzeHeaders(stubCase, req.body.rawEmail, normalized.headers)
//         ]);
//         // Tolerate either service being down — matches /submit's resilience.
//         // A missing piece just defaults to 0 inside computeRiskScore rather
//         // than failing the whole preview.
//         const detection = detectionResult.status === 'fulfilled' ? detectionResult.value : undefined;
//         const forensics = forensicsResult.status === 'fulfilled' ? forensicsResult.value : undefined;
//         return res.json(
//           buildReporterResponse({ caseId: null, detection, forensics, submittedAt: new Date() })
//         );
//       }

//       const verdict = await detectionService.analyze(stubCase);
//       res.json({ data: verdict });
//     } catch (err) {
//       res.status(502).json({ error: 'DETECTION_SERVICE_UNAVAILABLE', message: err.message });
//     }
//   }
// );

// /**
//  * POST /api/emails/submit
//  * Staff (admin/analyst): UNCHANGED — persists Case + Email, fires the
//  * pipeline fire-and-forget, responds 202 immediately with { caseId, status }.
//  *
//  * Reporter: persists Case + Email (reporter_id set), then AWAITS
//  * the full pipeline (detection + forensics + enrichment) before responding,
//  * so the redacted response always carries a real risk_score rather than a
//  * pending one. Rate-limited server-side via reporterDailySubmissionLimit —
//  * mounted after verifyJWT so req.user.role is already known, and it no-ops
//  * for staff callers.
//  */
// router.post(
//   '/submit',
//   requireRole('admin', 'analyst', 'reporter'),
//   reporterDailySubmissionLimit,
//   validate({
//     rawEmail: { required: true, type: 'string' },
//     sender: { required: true, type: 'string' }
//   }),
//   async (req, res) => {
//     const normalized = normalizeInput(req.body.rawEmail);
//     const isReporter = req.user.role === 'reporter';

//     const caseDoc = await Case.create({
//       sender: req.body.sender,
//       recipients: req.body.recipients || [],
//       subject: req.body.subject || normalized.subject,
//       submittedBy: isReporter ? undefined : req.user.id,
//       reporter_id: isReporter ? req.user.id : undefined,
//       channel: req.body.source === 'extension' ? 'extension' : 'api',
//       status: 'pending',
//       timeline: [{ stage: 'submitted', actor: req.user.id, summary: 'Case submitted', at: new Date() }]
//     });

//     await Email.create({
//       caseId: caseDoc._id,
//       rawContent: req.body.rawEmail,
//       parsedHeaders: normalized.headers,
//       source: req.body.source || 'api',
//       submittedBy: isReporter ? undefined : req.user.id
//     });

//     caseDoc.status = 'analyzing';
//     await caseDoc.save();

//     if (isReporter) {
//       // Reporter path: await the pipeline so risk_score is real, not pending.
//       try {
//         const finished = await orchestrator.runAnalysisPipeline(caseDoc, {
//           rawEmail: req.body.rawEmail,
//           headers: normalized.headers
//         });
//         return res.status(201).json(
//           buildReporterResponse({
//             caseId: finished._id,
//             detection: finished.detection,
//             forensics: finished.forensics,
//             submittedAt: finished.createdAt
//           })
//         );
//       } catch (err) {
//         // orchestrator is internally defensive (Promise.allSettled), so
//         // reaching here means something more fundamental broke (e.g. DB save).
//         return res
//           .status(502)
//           .json({ error: 'ANALYSIS_FAILED', message: 'Could not complete analysis, try again shortly' });
//       }
//     }

//     // Staff path: unchanged fire-and-forget.
//     orchestrator
//       .runAnalysisPipeline(caseDoc, { rawEmail: req.body.rawEmail, headers: normalized.headers })
//       .catch((err) => {
//         console.error(`Pipeline failed for case ${caseDoc._id}:`, err.message);
//       });

//     res.status(202).json({ data: { caseId: caseDoc._id, status: caseDoc.status } });
//   }
// );

// module.exports = router;







const express = require('express');
const router = express.Router();

const Case = require('../models/Case');
const Email = require('../models/Email');
const { verifyJWT, requireRole } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { reporterDailySubmissionLimit } = require('../middleware/rateLimiter');
const normalizeInput = require('../utils/normalizeInput');
const detectionService = require('../services/detectionService');
const forensicsService = require('../services/forensicsService');
const orchestrator = require('../services/orchestrator');
const { buildReporterResponse } = require('../utils/redactCaseResponse');

router.use(verifyJWT);

/**
 * POST /api/emails/analyze
 * Staff (admin/analyst): unchanged — fast detection-only preview, no persistence.
 * Reporter: also stays a preview (no Case is created), but runs detection +
 * forensics headers in parallel (not enrichment — too slow for an inline
 * check, and risk_score doesn't need it) so a real risk_score can be
 * returned. case_id is null here since nothing is persisted yet — a
 * reporter only gets a real case_id from /submit.
 */
router.post(
  '/analyze',
  requireRole('admin', 'analyst', 'reporter'),
  validate({ rawEmail: { required: true, type: 'string' } }),
  async (req, res) => {
    const normalized = normalizeInput(req.body.rawEmail);
    const stubCase = { sender: normalized.sender, subject: normalized.subject, rawEmail: req.body.rawEmail };

    try {
      if (req.user.role === 'reporter') {
        const [detectionResult, forensicsResult] = await Promise.allSettled([
          detectionService.analyze(stubCase),
          forensicsService.analyzeHeaders(stubCase, req.body.rawEmail, normalized.headers)
        ]);
        // Tolerate either service being down — matches /submit's resilience.
        // A missing piece just defaults to 0 inside computeRiskScore rather
        // than failing the whole preview.
        const detection = detectionResult.status === 'fulfilled' ? detectionResult.value : undefined;
        const forensics = forensicsResult.status === 'fulfilled' ? forensicsResult.value : undefined;
        const response = buildReporterResponse({ caseId: null, detection, forensics, submittedAt: new Date() });
        return res.json(response);
      }

      const verdict = await detectionService.analyze(stubCase);
      res.json({ data: verdict });
    } catch (err) {
      console.error('POST /emails/analyze failed:', err.stack || err.message);
      res.status(502).json({ error: 'DETECTION_SERVICE_UNAVAILABLE', message: err.message });
    }
  }
);

/**
 * POST /api/emails/submit
 * Staff (admin/analyst): UNCHANGED — persists Case + Email, fires the
 * pipeline fire-and-forget, responds 202 immediately with { caseId, status }.
 *
 * Reporter: persists Case + Email (reporter_id set), then AWAITS
 * the full pipeline (detection + forensics + enrichment) before responding,
 * so the redacted response always carries a real risk_score rather than a
 * pending one. Rate-limited server-side via reporterDailySubmissionLimit —
 * mounted after verifyJWT so req.user.role is already known, and it no-ops
 * for staff callers.
 */
router.post(
  '/submit',
  requireRole('admin', 'analyst', 'reporter'),
  reporterDailySubmissionLimit,
  validate({
    rawEmail: { required: true, type: 'string' },
    sender: { required: true, type: 'string' }
  }),
  async (req, res) => {
    const normalized = normalizeInput(req.body.rawEmail);
    const isReporter = req.user.role === 'reporter';

    const caseDoc = await Case.create({
      sender: req.body.sender,
      recipients: req.body.recipients || [],
      subject: req.body.subject || normalized.subject,
      submittedBy: isReporter ? undefined : req.user.id,
      reporter_id: isReporter ? req.user.id : undefined,
      channel: req.body.source === 'extension' ? 'extension' : 'api',
      status: 'pending',
      timeline: [{ stage: 'submitted', actor: req.user.id, summary: 'Case submitted', at: new Date() }]
    });

    await Email.create({
      caseId: caseDoc._id,
      rawContent: req.body.rawEmail,
      parsedHeaders: normalized.headers,
      source: req.body.source || 'api',
      submittedBy: isReporter ? undefined : req.user.id
    });

    caseDoc.status = 'analyzing';
    await caseDoc.save();

    if (isReporter) {
      // Reporter path: await the pipeline so risk_score is real, not pending.
      try {
        const finished = await orchestrator.runAnalysisPipeline(caseDoc, {
          rawEmail: req.body.rawEmail,
          headers: normalized.headers
        });
        return res.status(201).json(
          buildReporterResponse({
            caseId: finished._id,
            detection: finished.detection,
            forensics: finished.forensics,
            submittedAt: finished.createdAt
          })
        );
      } catch (err) {
        // orchestrator is internally defensive (Promise.allSettled), so
        // reaching here means something more fundamental broke (e.g. DB save,
        // a bug in buildReporterResponse, etc). Log the full error — this
        // catch was previously swallowing it silently.
        console.error(`POST /emails/submit (reporter) failed for case ${caseDoc._id}:`, err.stack || err.message);
        return res
          .status(502)
          .json({ error: 'ANALYSIS_FAILED', message: 'Could not complete analysis, try again shortly' });
      }
    }

    // Staff path: unchanged fire-and-forget.
    orchestrator
      .runAnalysisPipeline(caseDoc, { rawEmail: req.body.rawEmail, headers: normalized.headers })
      .catch((err) => {
        console.error(`Pipeline failed for case ${caseDoc._id}:`, err.message);
      });

    res.status(202).json({ data: { caseId: caseDoc._id, status: caseDoc.status } });
  }
);

module.exports = router;