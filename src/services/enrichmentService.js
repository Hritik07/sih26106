const axios = require('axios');

const BASE_URL = process.env.ENRICHMENT_SERVICE_URL; // e.g. https://sih26106-enrichment.onrender.com

/**
 * enrich(caseDoc, originIp)
 * Calls the GeoIP/WHOIS/enrichment microservice. Runs AFTER forensics —
 * originIp is the IP forensics already extracted from headers, so this
 * service does GeoIP/WHOIS lookups on a known-good value instead of
 * re-parsing headers itself (see orchestrator.runAnalysisPipeline, which
 * now sequences forensics -> enrichment rather than running them in
 * parallel).
 *
 * This service expects snake_case field names (case_id, origin_ip) — a
 * different convention than the forensics service, which accepted camelCase
 * without complaint. Confirmed via the "Invalid or missing field: case_id"
 * error when camelCase was sent.
 */
async function enrich(caseDoc, originIp) {
  const { data } = await axios.post(
    `${BASE_URL}/enrich`,
    { sender: caseDoc.sender, case_id: caseDoc._id.toString(), origin_ip: originIp },
    // Bumped alongside forensics' timeout — WHOIS/domain-age lookups against
    // real domains are likely to have the same real-DNS latency that made
    // forensics' 10s too tight for real emails.
    { timeout: 20_000 }
  );

  // Confirmed real shape: { geolocation: { status, country, city, isp,
  //   latitude, longitude }, infrastructure_type, domain_age_days,
  //   dns_mismatch_flags, campaign_cluster_id, processed_at }
  return data;
}

module.exports = { enrich };