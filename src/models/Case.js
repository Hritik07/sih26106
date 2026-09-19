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
//       enum: ['submitted', 'detection', 'forensics', 'enrichment', 'confirmed', 'report_generated', 'flagged', 'unflagged'],
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

//     // --- Analyst-raised flag for admin attention (separate from confirm —
//     // analysts can't confirm a threat, but they CAN escalate visibility on
//     // something urgent without needing to message an admin outside the app) ---
//     flagged: { type: Boolean, default: false, index: true },
//     flag_reason: { type: String, default: null },
//     flagged_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     flagged_at: { type: Date, default: null },

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



// V5 // 




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
//       enum: ['submitted', 'detection', 'forensics', 'enrichment', 'confirmed', 'report_generated', 'flagged', 'unflagged'],
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

//     // --- Analyst-raised flag for admin attention (separate from confirm —
//     // analysts can't confirm a threat, but they CAN escalate visibility on
//     // something urgent without needing to message an admin outside the app) ---
//     flagged: { type: Boolean, default: false, index: true },
//     flag_reason: { type: String, default: null },
//     flagged_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     flagged_at: { type: Date, default: null },

//     // --- Stage 1: ML/NLP detection microservice ---
//     // CONFIRMED against the service's real source code (not just Swagger).
//     detection: {
//       // Fixed set of exactly 4 values — the model can never output anything
//       // else. "suspicious" is an override applied when the raw prediction is
//       // phishing/bec but confidence is below 70%.
//       classification: { type: String, enum: ['legitimate', 'phishing', 'bec', 'suspicious'] },
//       // CONFIRMED scale: 0.0-100.0, one decimal place. NOT 0-1.
//       confidence_score: { type: Number, min: 0, max: 100 },
//       // CONFIRMED exact shape — a fixed 7-key object, not an array.
//       matched_indicators: {
//         urgency_score: { type: Number },
//         impersonation_score: { type: Number },
//         bec_score: { type: Number },
//         url_count: { type: Number },
//         has_attachment_mention: { type: Boolean },
//         excessive_punctuation: { type: Boolean },
//         generic_greeting: { type: Boolean }
//       },
//       processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
//     },

//     // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
//     // REWORKED — the forensics engineer confirmed (grepped from real source)
//     // that the service's response shape changed since we last tested it:
//     // `.status` is actually `.result`, `risk_band` is actually `risk_tier`,
//     // `confidence`/`module_status` never existed, anomaly_flags are objects
//     // not strings, and relay_path is a nested { hop_count, hops } structure
//     // rather than a flat array. earliest_trustworthy_ip is a NEW top-level
//     // field specifically meant to replace any hop-indexing we'd do ourselves.
//     forensics: {
//       message_id: { type: String },
//       from_address: { type: String },
//       from_domain: { type: String },
//       return_path_address: { type: String },
//       reply_to_address: { type: String },
//       spf_result: {
//         result: { type: String }, // full RFC 7208 set: pass|fail|softfail|neutral|none|permerror|temperror
//         checked_domain: { type: String },
//         checked_ip: { type: String },
//         explanation: { type: String }
//       },
//       dkim_result: {
//         result: { type: String }, // pass|fail|no_signature|temperror
//         checked_domain: { type: String },
//         selector: { type: String },
//         explanation: { type: String }
//       },
//       dmarc_result: {
//         result: { type: String }, // pass|fail|none|temperror
//         policy: { type: String, default: null },
//         explanation: { type: String }
//       },
//       // Kept as Mixed rather than a strict sub-schema — only hops[].index,
//       // .ip, and .claimed_host were confirmed explicitly; other per-hop
//       // fields exist but weren't fully enumerated, so Mixed avoids silently
//       // dropping data we haven't pinned down yet.
//       relay_path: { type: Schema.Types.Mixed },
//       // THE field to read for origin IP — replaces any hop-array-indexing
//       // logic. Already computed correctly (skips private/internal IPs) by
//       // the forensics service itself.
//       earliest_trustworthy_ip: { type: String, default: null },
//       anomaly_flags: [
//         {
//           _id: false,
//           code: { type: String }, // see forensics engineer's answer for the full ~15-code list
//           severity: { type: String }, // info|low|medium|high|critical
//           weight: { type: Number },
//           description: { type: String }
//         }
//       ],
//       spoofing_risk_score: { type: Number, min: 0, max: 100 }, // 0-100, feeds the reporter-facing risk_score
//       risk_tier: { type: String }, // clean|low|medium|high|critical — renamed from what we'd guessed as risk_band
//       score_reasons: [{ type: String }],
//       processing_errors: [{ type: String }],
//       processed_at: { type: Date } // stamped by forensicsService
//     },

//     // --- Stage 3: GeoIP/WHOIS enrichment microservice ---
//     // Shape confirmed correct via live testing AND the enrichment team's
//     // answers — the earlier "unknown" geolocation results were a real
//     // deploy bug on their side (missing .mmdb database file), now fixed.
//     enrichment: {
//       geolocation: {
//         status: { type: String }, // 'success' | 'unknown' — confirmed 'success' on a working real IP now that the DB is deployed
//         country: { type: String, default: null },
//         city: { type: String, default: null }, // may stay null even on success for anycast IPs (e.g. 8.8.8.8) — expected MaxMind limitation, not a bug
//         isp: { type: String, default: null }, // stays null unless the separate GeoLite2-ASN database is also deployed
//         latitude: { type: Number, default: null },
//         longitude: { type: Number, default: null }
//       },
//       // CONFIRMED full set: TOR | VPN | HOSTING | RESIDENTIAL | CORPORATE | UNKNOWN.
//       // RESIDENTIAL/CORPORATE are real enum values but only ever returned by
//       // their DEMO_MODE mock provider — the live classifier deliberately
//       // never guesses those two, falling back to UNKNOWN instead.
//       infrastructure_type: { type: String },
//       domain_age_days: { type: Number, default: null },
//       // CONFIRMED set: DOMAIN_NOT_RESOLVING | NO_MX_RECORD | DNS_LOOKUP_FAILED |
//       // SUSPICIOUS_DNS_CONFIGURATION | INFRASTRUCTURE_MISMATCH
//       dns_mismatch_flags: [{ type: String }],
//       // CONFIRMED supplementary, not authoritative — our own campaignClustering.js
//       // remains the primary system. Stable per case_id; stable across cases
//       // sharing an IP/domain IF the earlier case was successfully written to
//       // Mongo when processed (silent new-cluster fallback otherwise).
//       campaign_cluster_id: { type: String, default: null },
//       processed_at: { type: Date } // stamped by enrichmentService
//     },

//     // --- Campaign correlation (campaignClustering.js) ---
//     campaignId: { type: Schema.Types.ObjectId, ref: 'Campaign', default: null },

//     // --- Blockchain anchoring (set only after POST /api/cases/:id/confirm) ---
//     // blockchain_hash is now the AUTHORITATIVE hash returned directly by the
//     // detection service's /anchor response — we no longer compute our own
//     // hash locally (see orchestrator.confirmAndAnchor).
//     blockchain_hash: { type: String, default: null },
//     blockchain_tx_id: { type: String, default: null },
//     anchored_at: { type: Date, default: null },

//     // --- Report audit trail (set only after POST /api/cases/:id/report) ---
//     // Report assembly happens entirely on THIS backend now — there is no
//     // /report endpoint on any microservice (confirmed, never existed).
//     // report_data holds the actual assembled report content directly;
//     // reportRef is kept for backward compatibility but unused going forward.
//     report_data: { type: Schema.Types.Mixed, default: null },
//     report_generated_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     report_generated_at: { type: Date, default: null },
//     reportRef: { type: String, default: null }, // deprecated — see report_data

//     // --- Confirmation audit (who marked it a confirmed threat) ---
//     confirmed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
//     confirmed_at: { type: Date, default: null },

//     timeline: [TimelineEntrySchema]
//   },
//   { timestamps: true } // createdAt / updatedAt
// );

// // Fast lookups for the dashboard's default views
// CaseSchema.index({ status: 1, createdAt: -1 });
// CaseSchema.index({ 'detection.classification': 1 });

// module.exports = mongoose.model('Case', CaseSchema);



// V6 // 


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
    // CONFIRMED against the service's real source code, but kept loosely
    // typed rather than strictly enforced — the anomaly_flags crash proved
    // a live service's actual output CAN drift from its own team's
    // documentation, and a strict enum/min/max here would fail the same
    // way (either a CastError on assignment, or a ValidatorError on save)
    // the moment that happens. Documented expected shape stays in comments.
    detection: {
      // Documented set: legitimate | phishing | bec | suspicious — NOT enforced.
      classification: { type: String },
      // Documented scale: 0.0-100.0, one decimal place — NOT enforced.
      confidence_score: { type: Number },
      // Documented shape: { urgency_score, impersonation_score, bec_score,
      // url_count (numbers), has_attachment_mention, excessive_punctuation,
      // generic_greeting (booleans) } — kept as Mixed for the same reason.
      matched_indicators: { type: Schema.Types.Mixed },
      processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
    },

    // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
    // REWORKED — the forensics engineer confirmed (grepped from real source)
    // that the service's response shape changed since we last tested it:
    // `.status` is actually `.result`, `risk_band` is actually `risk_tier`,
    // `confidence`/`module_status` never existed, anomaly_flags are objects
    // not strings, and relay_path is a nested { hop_count, hops } structure
    // rather than a flat array. earliest_trustworthy_ip is a NEW top-level
    // field specifically meant to replace any hop-indexing we'd do ourselves.
    forensics: {
      message_id: { type: String },
      from_address: { type: String },
      from_domain: { type: String },
      return_path_address: { type: String },
      reply_to_address: { type: String },
      // Nested result objects kept as Mixed rather than strictly typed —
      // the anomaly_flags crash above proved the live service's actual
      // shape can drift from its own team's documentation. Plain JS
      // property access (e.g. spf_result?.result) works identically
      // whether Mongoose enforces a strict shape or not, so nothing in our
      // reading code changes — we just stop crashing on a drift.
      spf_result: { type: Schema.Types.Mixed }, // expect ~{ result, checked_domain, checked_ip, explanation }
      dkim_result: { type: Schema.Types.Mixed }, // expect ~{ result, checked_domain, selector, explanation }
      dmarc_result: { type: Schema.Types.Mixed }, // expect ~{ result, policy, explanation }
      // Kept as Mixed rather than a strict sub-schema — only hops[].index,
      // .ip, and .claimed_host were confirmed explicitly; other per-hop
      // fields exist but weren't fully enumerated, so Mixed avoids silently
      // dropping data we haven't pinned down yet.
      relay_path: { type: Schema.Types.Mixed },
      // THE field to read for origin IP — replaces any hop-array-indexing
      // logic. Already computed correctly (skips private/internal IPs) by
      // the forensics service itself.
      earliest_trustworthy_ip: { type: String, default: null },
      // Kept as Mixed — a LIVE crash on Render showed the deployed forensics
      // service is still returning this as an array of plain strings (e.g.
      // ["MISSING_HOPS"]), contradicting the object shape ({code, severity,
      // weight, description}) described in the forensics engineer's written
      // answer. That answer likely describes code not yet deployed, or a
      // different endpoint variant. Rather than trust either shape and risk
      // crashing again on the next drift, this field stays untyped — the
      // orchestrator/UI should defensively check `typeof` before treating
      // an entry as a string vs an object. Worth re-confirming with the
      // forensics teammate which shape is ACTUALLY live right now.
      anomaly_flags: { type: Schema.Types.Mixed, default: [] },
      spoofing_risk_score: { type: Number }, // documented 0-100, bound removed — same drift-risk reasoning as above
      risk_tier: { type: String }, // clean|low|medium|high|critical — renamed from what we'd guessed as risk_band
      score_reasons: [{ type: String }],
      processing_errors: [{ type: String }],
      processed_at: { type: Date } // stamped by forensicsService
    },

    // --- Stage 3: GeoIP/WHOIS enrichment microservice ---
    // Shape confirmed correct via live testing AND the enrichment team's
    // answers — the earlier "unknown" geolocation results were a real
    // deploy bug on their side (missing .mmdb database file), now fixed.
    enrichment: {
      geolocation: {
        status: { type: String }, // 'success' | 'unknown' — confirmed 'success' on a working real IP now that the DB is deployed
        country: { type: String, default: null },
        city: { type: String, default: null }, // may stay null even on success for anycast IPs (e.g. 8.8.8.8) — expected MaxMind limitation, not a bug
        isp: { type: String, default: null }, // stays null unless the separate GeoLite2-ASN database is also deployed
        latitude: { type: Number, default: null },
        longitude: { type: Number, default: null }
      },
      // CONFIRMED full set: TOR | VPN | HOSTING | RESIDENTIAL | CORPORATE | UNKNOWN.
      // RESIDENTIAL/CORPORATE are real enum values but only ever returned by
      // their DEMO_MODE mock provider — the live classifier deliberately
      // never guesses those two, falling back to UNKNOWN instead.
      infrastructure_type: { type: String },
      domain_age_days: { type: Number, default: null },
      // CONFIRMED set: DOMAIN_NOT_RESOLVING | NO_MX_RECORD | DNS_LOOKUP_FAILED |
      // SUSPICIOUS_DNS_CONFIGURATION | INFRASTRUCTURE_MISMATCH
      dns_mismatch_flags: [{ type: String }],
      // CONFIRMED supplementary, not authoritative — our own campaignClustering.js
      // remains the primary system. Stable per case_id; stable across cases
      // sharing an IP/domain IF the earlier case was successfully written to
      // Mongo when processed (silent new-cluster fallback otherwise).
      campaign_cluster_id: { type: String, default: null },
      processed_at: { type: Date } // stamped by enrichmentService
    },

    // --- Campaign correlation (campaignClustering.js) ---
    campaignId: { type: Schema.Types.ObjectId, ref: 'Campaign', default: null },

    // --- Blockchain anchoring (set only after POST /api/cases/:id/confirm) ---
    // blockchain_hash is now the AUTHORITATIVE hash returned directly by the
    // detection service's /anchor response — we no longer compute our own
    // hash locally (see orchestrator.confirmAndAnchor).
    blockchain_hash: { type: String, default: null },
    blockchain_tx_id: { type: String, default: null },
    anchored_at: { type: Date, default: null },

    // --- Report audit trail (set only after POST /api/cases/:id/report) ---
    // Report assembly happens entirely on THIS backend now — there is no
    // /report endpoint on any microservice (confirmed, never existed).
    // report_data holds the actual assembled report content directly;
    // reportRef is kept for backward compatibility but unused going forward.
    report_data: { type: Schema.Types.Mixed, default: null },
    report_generated_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    report_generated_at: { type: Date, default: null },
    reportRef: { type: String, default: null }, // deprecated — see report_data

    // --- Confirmation audit (who marked it a confirmed threat) ---
    confirmed_by: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    confirmed_at: { type: Date, default: null },

    timeline: [TimelineEntrySchema]
  },
  { timestamps: true } // createdAt / updatedAt
);

// Fast lookups for the dashboard's default views
CaseSchema.index({ status: 1, createdAt: -1 });
CaseSchema.index({ 'detection.classification': 1 });

module.exports = mongoose.model('Case', CaseSchema);