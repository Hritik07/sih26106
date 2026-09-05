const crypto = require('crypto');
const Campaign = require('../models/Campaign');

/**
 * assignCampaign(caseDoc)
 *
 * Called by the orchestrator once enrichment lands. Builds a clusterKey
 * from signals that are stable across a phishing wave (ASN + sender domain
 * + threat type) — deliberately NOT including the individual originIp,
 * since a single campaign often rotates IPs within the same ASN/domain.
 *
 * Cases sharing a clusterKey join the same Campaign document; a new one is
 * created on first sight of that fingerprint.
 */
async function assignCampaign(caseDoc) {
  const senderDomain = (caseDoc.sender || '').split('@')[1] || 'unknown';
  const fingerprint = [caseDoc.enrichment?.asn || 'unknown-asn', senderDomain, caseDoc.detection?.threatType || 'unknown'].join(
    '|'
  );
  const clusterKey = crypto.createHash('sha1').update(fingerprint).digest('hex');

  let campaign = await Campaign.findOne({ clusterKey });

  if (!campaign) {
    campaign = await Campaign.create({
      clusterKey,
      threatType: caseDoc.detection?.threatType,
      caseIds: [caseDoc._id],
      caseCount: 1,
      firstSeenAt: caseDoc.createdAt,
      lastSeenAt: caseDoc.createdAt,
      sharedIndicators: caseDoc.detection?.indicators || []
    });
  } else if (!campaign.caseIds.some((id) => id.equals(caseDoc._id))) {
    campaign.caseIds.push(caseDoc._id);
    campaign.caseCount += 1;
    campaign.lastSeenAt = new Date();
    // union indicators without duplicating
    const merged = new Set([...campaign.sharedIndicators, ...(caseDoc.detection?.indicators || [])]);
    campaign.sharedIndicators = [...merged];
    await campaign.save();
  }

  return campaign._id;
}

module.exports = { assignCampaign };