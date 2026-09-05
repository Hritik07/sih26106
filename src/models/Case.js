// const mongoose = require('mongoose');
// const { Schema } = mongoose;

// /**
//  * Timeline entries are the append-only log the report generator reads from.
//  * Every stage (detection / forensics / enrichment / confirm / report) pushes
//  * exactly one entry when it completes, so the array is always in
//  * chronological order without needing a sort at report time.
//  */
// const TimelineEntrySchema = new Schema(
//   {
//     stage: {
//       type: String,
//       enum: ['submitted', 'detection', 'forensics', 'enrichment', 'confirmed', 'report_generated'],
//       required: true
//     },
//     actor: { type: String, default: 'system' }, // 'system' for microservices, userId for human actions
//     summary: { type: String, required: true }, // short human-readable line, e.g. "Detection: phishing (0.94 confidence)"
//     at: { type: Date, default: Date.now }
//   },
//   { _id: false }
// );

// const CaseSchema = new Schema(
//   {
//     // --- Source email ---
//     sender: { type: String, required: true, index: true },
//     recipients: [{ type: String }],
//     subject: { type: String },
//     rawEmailRef: { type: String }, // pointer to stored .eml (S3/local), not the raw body inline
//     submittedBy: { type: Schema.Types.ObjectId, ref: 'User' }, // set when a staff member (admin/analyst) submits directly

//     // Set only for reporter-originated submissions. IMAP-sourced cases leave
//     // this null by design — they're institutional, not tied to a signed-up
//     // person, and no reporter-matching logic runs for that channel.
//     reporter_id: { type: Schema.Types.ObjectId, ref: 'Reporter', default: null },
//     channel: { type: String, enum: ['extension', 'manual_upload', 'api', 'imap'], default: 'api' },

//     // --- Case lifecycle ---
//     status: {
//       type: String,
//       enum: ['pending', 'analyzing', 'investigating', 'confirmed', 'dismissed'],
//       default: 'pending',
//       index: true
//     },

//     // --- Stage 1: ML/NLP detection microservice ---
//     detection: {
//       isPhishing: { type: Boolean },
//       threatType: { type: String }, // e.g. 'phishing', 'BEC', 'malware_link', 'spam'
//       confidence: { type: Number, min: 0, max: 1 },
//       indicators: [{ type: String }], // e.g. ['urgency_language', 'lookalike_domain']
//       modelVersion: { type: String },
//       processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
//     },

//     // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
//     forensics: {
//       spf: { type: String, enum: ['pass', 'fail', 'softfail', 'neutral', 'none', null] },
//       dkim: { type: String, enum: ['pass', 'fail', 'none', null] },
//       dmarc: { type: String, enum: ['pass', 'fail', 'none', null] },
//       returnPathDomain: { type: String },
//       fromDomainMismatch: { type: Boolean },
//       headerAnomalies: [{ type: String }],
//       spoofingRiskScore: { type: Number, min: 0, max: 100 }, // 0-100, feeds the reporter-facing risk_score
//       extractedIp: { type: String }, // originating IP pulled from headers — enrichment runs off this, not raw headers again
//       processed_at: { type: Date } // stamped by forensicsService
//     },

//     // --- Stage 3: GeoIP/WHOIS enrichment microservice ---
//     enrichment: {
//       originIp: { type: String },
//       geo: {
//         country: { type: String },
//         region: { type: String },
//         city: { type: String },
//         lat: { type: Number },
//         lon: { type: Number }
//       },
//       whois: {
//         registrar: { type: String },
//         domainCreatedAt: { type: Date },
//         domainAgeDays: { type: Number }
//       },
//       asn: { type: String },
//       processed_at: { type: Date } // stamped by enrichmentService
//     },

//     // --- Campaign correlation (campaignClustering.js) ---
//     campaignId: { type: Schema.Types.ObjectId, ref: 'Campaign', default: null },

//     // --- Blockchain anchoring (set only after POST /api/cases/:id/confirm) ---
//     blockchain_hash: { type: String, default: null }, // sha256 of the finalized case snapshot
//     blockchain_tx_id: { type: String, default: null }, // tx id on the anchoring chain
//     anchored_at: { type: Date, default: null },

//     // --- Report audit trail (set only after POST /api/cases/:id/report) ---
//     report_generated_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     report_generated_at: { type: Date, default: null },
//     reportRef: { type: String, default: null }, // pointer to generated PDF/report artifact

//     // --- Confirmation audit (who marked it a confirmed threat) ---
//     confirmed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     confirmed_at: { type: Date, default: null },

//     timeline: [TimelineEntrySchema]
//   },
//   { timestamps: true } // createdAt / updatedAt
// );

// // Fast lookups for the dashboard's default views
// CaseSchema.index({ status: 1, createdAt: -1 });
// CaseSchema.index({ 'detection.threatType': 1 });

// module.exports = mongoose.model('Case', CaseSchema);




// V2 //




// const mongoose = require('mongoose');
// const { Schema } = mongoose;

// /**
//  * Timeline entries are the append-only log the report generator reads from.
//  * Every stage (detection / forensics / enrichment / confirm / report) pushes
//  * exactly one entry when it completes, so the array is always in
//  * chronological order without needing a sort at report time.
//  */
// const TimelineEntrySchema = new Schema(
//   {
//     stage: {
//       type: String,
//       enum: ['submitted', 'detection', 'forensics', 'enrichment', 'confirmed', 'report_generated'],
//       required: true
//     },
//     actor: { type: String, default: 'system' }, // 'system' for microservices, userId for human actions
//     summary: { type: String, required: true }, // short human-readable line, e.g. "Detection: phishing (0.94 confidence)"
//     at: { type: Date, default: Date.now }
//   },
//   { _id: false }
// );

// const CaseSchema = new Schema(
//   {
//     // --- Source email ---
//     sender: { type: String, required: true, index: true },
//     recipients: [{ type: String }],
//     subject: { type: String },
//     rawEmailRef: { type: String }, // pointer to stored .eml (S3/local), not the raw body inline
//     submittedBy: { type: Schema.Types.ObjectId, ref: 'User' }, // set when a staff member (admin/analyst) submits directly

//     // Set only for reporter-originated submissions. IMAP-sourced cases leave
//     // this null by design — they're institutional, not tied to a signed-up
//     // person, and no reporter-matching logic runs for that channel.
//     reporter_id: { type: Schema.Types.ObjectId, ref: 'Reporter', default: null },
//     channel: { type: String, enum: ['extension', 'manual_upload', 'api', 'imap'], default: 'api' },

//     // --- Case lifecycle ---
//     status: {
//       type: String,
//       enum: ['pending', 'analyzing', 'investigating', 'confirmed', 'dismissed'],
//       default: 'pending',
//       index: true
//     },

//     // --- Stage 1: ML/NLP detection microservice ---
//     detection: {
//       isPhishing: { type: Boolean },
//       threatType: { type: String }, // e.g. 'phishing', 'BEC', 'malware_link', 'spam'
//       confidence: { type: Number, min: 0, max: 1 },
//       indicators: [{ type: String }], // e.g. ['urgency_language', 'lookalike_domain']
//       modelVersion: { type: String },
//       processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
//     },

//     // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
//     // Field names match the forensics service's real response exactly
//     // (confirmed via a live test call) — this service uses snake_case.
//     forensics: {
//       message_id: { type: String },
//       from_address: { type: String },
//       from_domain: { type: String },
//       return_path_address: { type: String },
//       reply_to_address: { type: String },
//       spf_result: {
//         status: { type: String }, // 'pass' | 'fail' | 'softfail' | 'neutral' | 'none'
//         checked_domain: { type: String },
//         checked_ip: { type: String },
//         explanation: { type: String }
//       },
//       dkim_result: {
//         status: { type: String },
//         checked_domain: { type: String },
//         selector: { type: String },
//         explanation: { type: String }
//       },
//       dmarc_result: {
//         status: { type: String },
//         policy: { type: String, default: null },
//         explanation: { type: String }
//       },
//       relay_path: [
//         {
//           _id: false,
//           hop: Number,
//           server: String,
//           timestamp: String,
//           from_host: String,
//           from_ip: String, // origin IP is derived FROM this array — see deriveOriginIp() in orchestrator.js
//           by_host: String,
//           protocol: String,
//           smtp_id: String,
//           raw: String,
//           hop_index: Number
//         }
//       ],
//       anomaly_flags: [{ type: String }],
//       spoofing_risk_score: { type: Number, min: 0, max: 100 }, // 0-100, feeds the reporter-facing risk_score
//       risk_band: { type: String }, // 'low' | 'medium' | 'high' etc.
//       confidence: { type: String }, // categorical ('low'/'medium'/'high') — NOT the same as detection.confidence (0-1 numeric)
//       score_reasons: [{ type: String }],
//       module_status: {
//         relay: String,
//         spf: String,
//         dkim: String,
//         dmarc: String
//       },
//       processing_errors: [{ type: String }],
//       processed_at: { type: Date } // stamped by forensicsService
//     },

//     // --- Stage 3: GeoIP/WHOIS enrichment microservice ---
//     // Field names match the enrichment service's real response exactly
//     // (confirmed via a live test call). Note: this service does NOT echo
//     // back an origin IP (it only receives one as input) — for display, use
//     // the IP already captured in forensics.relay_path instead.
//     enrichment: {
//       geolocation: {
//         status: { type: String }, // 'known' | 'unknown'
//         country: { type: String, default: null },
//         city: { type: String, default: null },
//         isp: { type: String, default: null },
//         latitude: { type: Number, default: null },
//         longitude: { type: Number, default: null }
//       },
//       infrastructure_type: { type: String }, // e.g. 'UNKNOWN', 'DATACENTER', 'RESIDENTIAL'
//       domain_age_days: { type: Number, default: null },
//       dns_mismatch_flags: [{ type: String }],
//       // The enrichment service runs its own clustering independently of our
//       // campaignClustering.js — this is THEIR cluster id, kept for reference,
//       // separate from our own `campaignId` field below. Worth reconciling
//       // with the team on which is authoritative before the report/dashboard
//       // relies on either one.
//       campaign_cluster_id: { type: String, default: null },
//       processed_at: { type: Date } // stamped by enrichmentService
//     },

//     // --- Campaign correlation (campaignClustering.js) ---
//     campaignId: { type: Schema.Types.ObjectId, ref: 'Campaign', default: null },

//     // --- Blockchain anchoring (set only after POST /api/cases/:id/confirm) ---
//     blockchain_hash: { type: String, default: null }, // sha256 of the finalized case snapshot
//     blockchain_tx_id: { type: String, default: null }, // tx id on the anchoring chain
//     anchored_at: { type: Date, default: null },

//     // --- Report audit trail (set only after POST /api/cases/:id/report) ---
//     report_generated_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     report_generated_at: { type: Date, default: null },
//     reportRef: { type: String, default: null }, // pointer to generated PDF/report artifact

//     // --- Confirmation audit (who marked it a confirmed threat) ---
//     confirmed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     confirmed_at: { type: Date, default: null },

//     timeline: [TimelineEntrySchema]
//   },
//   { timestamps: true } // createdAt / updatedAt
// );

// // Fast lookups for the dashboard's default views
// CaseSchema.index({ status: 1, createdAt: -1 });
// CaseSchema.index({ 'detection.threatType': 1 });

// module.exports = mongoose.model('Case', CaseSchema);





// V4 //




const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Timeline entries are the append-only log the report generator reads from.
 * Every stage (detection / forensics / enrichment / confirm / report) pushes
 * exactly one entry when it completes, so the array is always in
 * chronological order without needing a sort at report time.
 */
const TimelineEntrySchema = new Schema(
  {
    stage: {
      type: String,
      enum: ['submitted', 'detection', 'forensics', 'enrichment', 'confirmed', 'report_generated', 'flagged', 'unflagged'],
      required: true
    },
    actor: { type: String, default: 'system' }, // 'system' for microservices, userId for human actions
    summary: { type: String, required: true }, // short human-readable line, e.g. "Detection: phishing (0.94 confidence)"
    at: { type: Date, default: Date.now }
  },
  { _id: false }
);

const CaseSchema = new Schema(
  {
    // --- Source email ---
    sender: { type: String, required: true, index: true },
    recipients: [{ type: String }],
    subject: { type: String },
    rawEmailRef: { type: String }, // pointer to stored .eml (S3/local), not the raw body inline
    submittedBy: { type: Schema.Types.ObjectId, ref: 'User' }, // set when a staff member (admin/analyst) submits directly

    // Set only for reporter-originated submissions. IMAP-sourced cases leave
    // this null by design — they're institutional, not tied to a signed-up
    // person, and no reporter-matching logic runs for that channel.
    reporter_id: { type: Schema.Types.ObjectId, ref: 'Reporter', default: null },
    channel: { type: String, enum: ['extension', 'manual_upload', 'api', 'imap'], default: 'api' },

    // --- Case lifecycle ---
    status: {
      type: String,
      enum: ['pending', 'analyzing', 'investigating', 'confirmed', 'dismissed'],
      default: 'pending',
      index: true
    },

    // --- Analyst-raised flag for admin attention (separate from confirm —
    // analysts can't confirm a threat, but they CAN escalate visibility on
    // something urgent without needing to message an admin outside the app) ---
    flagged: { type: Boolean, default: false, index: true },
    flag_reason: { type: String, default: null },
    flagged_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    flagged_at: { type: Date, default: null },

    // --- Stage 1: ML/NLP detection microservice ---
    detection: {
      isPhishing: { type: Boolean },
      threatType: { type: String }, // e.g. 'phishing', 'BEC', 'malware_link', 'spam'
      confidence: { type: Number, min: 0, max: 1 },
      indicators: [{ type: String }], // e.g. ['urgency_language', 'lookalike_domain']
      modelVersion: { type: String },
      processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
    },

    // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
    // Field names match the forensics service's real response exactly
    // (confirmed via a live test call) — this service uses snake_case.
    forensics: {
      message_id: { type: String },
      from_address: { type: String },
      from_domain: { type: String },
      return_path_address: { type: String },
      reply_to_address: { type: String },
      spf_result: {
        status: { type: String }, // 'pass' | 'fail' | 'softfail' | 'neutral' | 'none'
        checked_domain: { type: String },
        checked_ip: { type: String },
        explanation: { type: String }
      },
      dkim_result: {
        status: { type: String },
        checked_domain: { type: String },
        selector: { type: String },
        explanation: { type: String }
      },
      dmarc_result: {
        status: { type: String },
        policy: { type: String, default: null },
        explanation: { type: String }
      },
      relay_path: [
        {
          _id: false,
          hop: Number,
          server: String,
          timestamp: String,
          from_host: String,
          from_ip: String, // origin IP is derived FROM this array — see deriveOriginIp() in orchestrator.js
          by_host: String,
          protocol: String,
          smtp_id: String,
          raw: String,
          hop_index: Number
        }
      ],
      anomaly_flags: [{ type: String }],
      spoofing_risk_score: { type: Number, min: 0, max: 100 }, // 0-100, feeds the reporter-facing risk_score
      risk_band: { type: String }, // 'low' | 'medium' | 'high' etc.
      confidence: { type: String }, // categorical ('low'/'medium'/'high') — NOT the same as detection.confidence (0-1 numeric)
      score_reasons: [{ type: String }],
      module_status: {
        relay: String,
        spf: String,
        dkim: String,
        dmarc: String
      },
      processing_errors: [{ type: String }],
      processed_at: { type: Date } // stamped by forensicsService
    },

    // --- Stage 3: GeoIP/WHOIS enrichment microservice ---
    // Field names match the enrichment service's real response exactly
    // (confirmed via a live test call). Note: this service does NOT echo
    // back an origin IP (it only receives one as input) — for display, use
    // the IP already captured in forensics.relay_path instead.
    enrichment: {
      geolocation: {
        status: { type: String }, // 'known' | 'unknown'
        country: { type: String, default: null },
        city: { type: String, default: null },
        isp: { type: String, default: null },
        latitude: { type: Number, default: null },
        longitude: { type: Number, default: null }
      },
      infrastructure_type: { type: String }, // e.g. 'UNKNOWN', 'DATACENTER', 'RESIDENTIAL'
      domain_age_days: { type: Number, default: null },
      dns_mismatch_flags: [{ type: String }],
      // The enrichment service runs its own clustering independently of our
      // campaignClustering.js — this is THEIR cluster id, kept for reference,
      // separate from our own `campaignId` field below. Worth reconciling
      // with the team on which is authoritative before the report/dashboard
      // relies on either one.
      campaign_cluster_id: { type: String, default: null },
      processed_at: { type: Date } // stamped by enrichmentService
    },

    // --- Campaign correlation (campaignClustering.js) ---
    campaignId: { type: Schema.Types.ObjectId, ref: 'Campaign', default: null },

    // --- Blockchain anchoring (set only after POST /api/cases/:id/confirm) ---
    blockchain_hash: { type: String, default: null }, // sha256 of the finalized case snapshot
    blockchain_tx_id: { type: String, default: null }, // tx id on the anchoring chain
    anchored_at: { type: Date, default: null },

    // --- Report audit trail (set only after POST /api/cases/:id/report) ---
    report_generated_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    report_generated_at: { type: Date, default: null },
    reportRef: { type: String, default: null }, // pointer to generated PDF/report artifact

    // --- Confirmation audit (who marked it a confirmed threat) ---
    confirmed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    confirmed_at: { type: Date, default: null },

    timeline: [TimelineEntrySchema]
  },
  { timestamps: true } // createdAt / updatedAt
);

// Fast lookups for the dashboard's default views
CaseSchema.index({ status: 1, createdAt: -1 });
CaseSchema.index({ 'detection.threatType': 1 });

module.exports = mongoose.model('Case', CaseSchema);