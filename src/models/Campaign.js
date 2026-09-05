const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * A Campaign groups Cases that campaignClustering.js decided share an
 * origin — matching ASN/domain-age/indicator fingerprint. clusterKey is the
 * deterministic string clustering hashed to reach this group, kept for
 * debugging why cases were/weren't grouped together.
 */
const CampaignSchema = new Schema(
  {
    clusterKey: { type: String, required: true, index: true },
    threatType: { type: String },
    caseIds: [{ type: Schema.Types.ObjectId, ref: 'Case' }],
    caseCount: { type: Number, default: 0 },
    firstSeenAt: { type: Date },
    lastSeenAt: { type: Date },
    sharedIndicators: [{ type: String }] // union of indicators seen across member cases
  },
  { timestamps: true }
);

module.exports = mongoose.model('Campaign', CampaignSchema);