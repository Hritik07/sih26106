const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Stores the raw submission separately from Case so Case can stay lean for
 * dashboard list views (GET /api/cases excludes heavy raw content already).
 * One Email doc per submission; caseId is set once /emails/submit creates
 * the corresponding Case.
 */
const EmailSchema = new Schema(
  {
    caseId: { type: Schema.Types.ObjectId, ref: 'Case', index: true },
    rawContent: { type: String, required: true }, // full .eml / MIME source
    parsedHeaders: { type: Schema.Types.Mixed }, // raw header key/value map, pre-forensics-parse
    source: { type: String, enum: ['extension', 'manual_upload', 'api'], default: 'api' },
    submittedBy: { type: Schema.Types.ObjectId, ref: 'User' }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Email', EmailSchema);