const mongoose = require('mongoose');
const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    name: { type: String },
    role: { type: String, enum: ['admin', 'analyst'], default: 'analyst', required: true },

    // Forces a real password to be set on first login, before any session
    // is issued — an admin-created account starts with a temp password the
    // admin knows, which is a real (if brief) exposure; this closes it by
    // requiring the new user to replace it before they can do anything.
    mustChangePassword: { type: Boolean, default: true },

    // Login-time OTP (2FA), only reached once mustChangePassword is false.
    // Same four fields, same shape, same semantics as Reporter's OTP
    // fields — otpService.issueOtp/verifyOtp/clearOtp are written generically
    // against any document with these fields and reporter.email, so they're
    // reused as-is here with zero changes to otpService.js itself.
    otpHash: { type: String, default: null },
    otpExpiresAt: { type: Date, default: null },
    otpPurpose: { type: String, default: null },
    otpAttempts: { type: Number, default: 0 },

    // Forgot-password flow. Unlike the OTP fields above, this is looked up
    // by its OWN hash (User.findOne({ resetPasswordTokenHash })) rather than
    // by user id first — the reset link only carries the raw token, nothing
    // that identifies the account, so the hash itself has to be the lookup
    // key. The raw token is a bearer credential for exactly one action
    // (setting a new password) and is never stored or logged, same as an
    // OTP code never is.
    resetPasswordTokenHash: { type: String, default: null, index: true },
    resetPasswordExpiresAt: { type: Date, default: null }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);