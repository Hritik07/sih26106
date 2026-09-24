const axios = require('axios');

const BASE_URL = process.env.ENRICHMENT_SERVICE_URL; // e.g. https://sih26106-enrichment-service.onrender.com

/**
 * senderDomain(sender)
 * Enrichment's /enrich wants a bare domain, not a full address — sender is
 * stored as a full "user@domain" string (normalizeInput.js), so this strips
 * it down before sending.
 */
function senderDomain(sender) {
  if (typeof sender !== 'string') return undefined;
  const at = sender.lastIndexOf('@');
  if (at === -1) return undefined;
  const domain = sender.slice(at + 1).trim().replace(/[>\s]+$/, '').toLowerCase();
  return domain || undefined;
}

/**
 * enrich(caseDoc, originIp)
 * Calls the GeoIP/WHOIS/enrichment microservice. Runs AFTER forensics —
 * originIp is the IP forensics already extracted from headers, so this
 * service does GeoIP/WHOIS lookups on a known-good value instead of
 * re-parsing headers itself (see orchestrator.runAnalysisPipeline, which
 * now sequences forensics -> enrichment rather than running them in
 * parallel).
 *
 * Wire contract CONFIRMED against the service's EnrichRequest model
 * (main.py): case_id (required), originating_ip (NOT origin_ip), domain
 * (bare domain, not a full address), sender_domain (accepted but never
 * read by /enrich — sent anyway for forward-compat). The model doesn't set
 * extra="forbid", so any other key is silently dropped by pydantic rather
 * than rejected — this is why the old { sender, case_id, origin_ip }
 * payload returned HTTP 200 with every enrichment field empty instead of
 * an error.
 */
async function enrich(caseDoc, originIp) {
  const payload = { case_id: caseDoc._id.toString() };

  if (originIp) payload.originating_ip = originIp;

  const domain = senderDomain(caseDoc.sender);
  if (domain) {
    payload.domain = domain;
    payload.sender_domain = domain;
  }

  const { data } = await axios.post(
    `${BASE_URL}/enrich`,
    payload,
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

/**
 * enrichRelayHops(caseDoc, ips)
 * Calls POST /geoip/batch on the enrichment service to geolocate every
 * relay hop's IP, not just the single derived origin — powers the
 * multi-point "Relay Trace & Origin" map on the case detail page.
 *
 * ips: array of raw from_ip strings straight from forensics.relay_path,
 * IN ORDER, including private IPs and empty strings — the service
 * validates/classifies each entry itself (private_ip, invalid_input, etc.),
 * so nothing needs pre-filtering here.
 *
 * Response is positional: results[i] corresponds to ips[i]. The caller
 * (orchestrator.js) is responsible for keeping that index alignment when
 * writing into caseDoc.enrichment.relay_geolocation — never match these
 * back up by IP string, since relay_path can contain duplicate/empty
 * from_ip values.
 */
async function enrichRelayHops(caseDoc, ips) {
  if (!Array.isArray(ips) || ips.length === 0) return [];

  const { data } = await axios.post(
    `${BASE_URL}/geoip/batch`,
    { case_id: caseDoc._id.toString(), ips },
    // Local MaxMind lookups only, run concurrently on their side — should
    // be well within a single /enrich call's budget even at the 25-item cap.
    { timeout: 10_000 }
  );

  // Confirmed shape: { results: [{ ip, geolocation: { status, country,
  //   city, isp, latitude, longitude } }], processed_at }
  return Array.isArray(data?.results) ? data.results : [];
}

module.exports = { enrich, enrichRelayHops, senderDomain };