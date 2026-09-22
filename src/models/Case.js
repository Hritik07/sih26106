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
      // Per-class probability breakdown (legitimate/phishing/bec). Was
      // briefly absent from /classify's response during an unrelated
      // false-positive patch, then confirmed restored — added here
      // explicitly because it was NOT a declared field: without this, it
      // would be silently stripped on every save (Mongoose's default
      // strict-mode behavior drops any key not in the schema), even though
      // the service was sending it correctly the whole time.
      model_probabilities: { type: Schema.Types.Mixed },
      // Documented shape: { urgency_score, impersonation_score, bec_score,
      // url_count (numbers), has_attachment_mention, excessive_punctuation,
      // generic_greeting (booleans) } — kept as Mixed for the same reason.
      matched_indicators: { type: Schema.Types.Mixed },
      processed_at: { type: Date } // stamped by detectionService, not by the orchestrator
    },

    // --- Stage 2: Header/SPF-DKIM-DMARC forensics microservice ---
    // CONFIRMED directly against the service's real deployed source code
    // (main.py, relay_parser.py, spf_check.py, dkim_check.py, dmarc_check.py)
    // — not inferred from live responses alone. This resolves the earlier
    // confusion: an EARLIER written answer described a different, not-
    // actually-deployed shape (risk_tier, .result fields, nested relay_path,
    // earliest_trustworthy_ip) — none of that exists in the real code. The
    // shape below is the genuine, verified contract.
    forensics: {
      // Top-level API envelope — informational only, not used in any logic.
      // Field names match the real response exactly ("status"/"service" —
      // not renamed, despite "status" appearing elsewhere too on nested
      // objects like spf.status; Mongoose scopes each by its parent path).
      status: { type: String }, // 'success' | 'partial_success'
      service: { type: String }, // always "forensics-service"

      spf: {
        status: { type: String }, // pass|fail|softfail|neutral|none|temperror|permerror|error
        checked_domain: { type: String },
        checked_ip: { type: String },
        explanation: { type: String }
      },
      dkim: {
        status: { type: String }, // pass|fail|none|temperror|error
        checked_domain: { type: String },
        selector: { type: String },
        explanation: { type: String }
      },
      dmarc: {
        status: { type: String }, // pass|fail|none|temperror|error
        policy: { type: String, default: null }, // none|quarantine|reject
        pct: { type: Number },
        spf_aligned: { type: Boolean },
        dkim_aligned: { type: Boolean },
        alignment_mode: { aspf: String, adkim: String },
        alignment_check_simplified: { type: Boolean }, // true = naive "last two labels" heuristic, not a real Public Suffix List
        explanation: { type: String }
      },
      // Health of each validator component itself — separate from the
      // actual SPF/DKIM/DMARC verdicts above (a validator can be "ok" while
      // its result is "fail", or "error" if the check itself couldn't run).
      forensic_service: {
        status: { type: String }, // working|degraded
        relay: { type: String },
        spf: { type: String },
        dkim: { type: String },
        dmarc: { type: String }
      },
      email: {
        message_id: { type: String },
        from_address: { type: String },
        from_domain: { type: String },
        return_path_address: { type: String },
        reply_to_address: { type: String }
      },
      // Flat array, CONFIRMED chronological — index 0 is the OLDEST hop
      // (closest to true origin), NOT the newest. See deriveOriginIp() in
      // orchestrator.js, which reads from index 0 forward and skips private
      // IPs (real example: hop 0 was an internal relay IP, not the actual
      // public sending IP).
      relay_path: [
        {
          _id: false,
          hop: Number,
          server: String,
          timestamp: String,
          from_host: String,
          from_ip: String,
          by_host: String,
          protocol: String,
          smtp_id: String,
          raw: String,
          hop_index: Number
        }
      ],
      // CONFIRMED exact set — only 4 possible values, not the ~15-code list
      // an earlier written answer described (that was for undeployed logic):
      // MISSING_HOPS | OUT_OF_ORDER_TIMESTAMP | RETURN_PATH_MISMATCH | ORIGIN_DOMAIN_MISMATCH
      anomaly_flags: [{ type: String }],
      spoofing_risk_score: { type: Number, min: 0, max: 100 }, // confirmed capped at 100
      risk_band: { type: String }, // low|medium|high|critical — confirmed thresholds: <25 low, 25-49 medium, 50-74 high, >=75 critical
      // low|medium|high — based on how many of SPF/DKIM/DMARC returned an
      // inconclusive status (temperror/permerror/error/none): 0=high, 1=medium, 2+=low.
      confidence: { type: String },
      score_reasons: [{ type: String }],
      processing_errors: [{ type: String }],
      processed_at: { type: Date } // stamped by forensicsService (ISO string, auto-cast to Date)
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
      processed_at: { type: Date }, // stamped by enrichmentService

      // Per-hop GeoIP results from POST /geoip/batch on the enrichment
      // service, aligned 1:1 with forensics.relay_path BY ARRAY INDEX
      // (relay_geolocation[i] corresponds to relay_path[i]) — never match
      // these up by IP string, since relay_path can contain empty/duplicate
      // from_ip values. Populated only when relay_path had at least one
      // entry and the batch call succeeded; stays an empty array otherwise
      // (e.g. forensics returned no hops, or the batch call itself failed —
      // the rest of enrichment still applies even if this one call didn't).
      relay_geolocation: [
        {
          _id: false,
          ip: { type: String }, // echoed back from the request, unchanged/unnormalized
          status: { type: String }, // 'success' | 'unknown' | 'private_ip' | 'not_found' | 'database_unavailable' | 'invalid_input'
          country: { type: String, default: null },
          city: { type: String, default: null },
          isp: { type: String, default: null },
          latitude: { type: Number, default: null },
          longitude: { type: Number, default: null }
        }
      ]
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