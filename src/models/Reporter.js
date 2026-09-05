const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Public reporter accounts — deliberately separate from the staff `User`
 * collection (admin/analyst). No age, gender, or government ID fields by
 * design (see PART A of the spec) — this is intentionally minimal so the
 * platform never becomes a PII liability for anonymous-ish public reporting.
 *
 * email_verified reflects email-OTP verification (not phone) — phone is
 * collected for contact purposes only and is never itself OTP-verified.
 */
const ReporterSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    phone: { type: String, trim: true },
    organization: { type: String, trim: true }, // optional
    email_verified: { type: Boolean, default: false },

    // --- OTP challenge state (one active challenge at a time) ---
    otpHash: { type: String, default: null }, // sha256 of the 6-digit code, never store plaintext
    otpExpiresAt: { type: Date, default: null },
    otpPurpose: { type: String, enum: ['signup', 'login', null], default: null },
    otpAttempts: { type: Number, default: 0 }, // failed verify attempts against the current challenge

    created_at: { type: Date, default: Date.now }
  },
  { timestamps: false } // created_at is explicit per spec; no updatedAt needed
);

module.exports = mongoose.model('Reporter', ReporterSchema);