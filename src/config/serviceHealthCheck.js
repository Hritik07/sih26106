const axios = require('axios');

/**
 * checkMicroservices()
 *
 * Fires a quick GET /health at each teammate's service on startup and logs
 * whether it's reachable — the closest equivalent to "MongoDB connected"
 * for services we don't hold a persistent connection to. Non-fatal: a
 * service being down does NOT crash the backend or block it from starting,
 * since the orchestrator already handles a service being unavailable at
 * request time (Promise.allSettled). This is a startup diagnostic only.
 *
 * ASSUMES each microservice exposes a GET /health route returning any 2xx
 * response. If a teammate's service doesn't have one yet, ask them to add
 * a trivial one (e.g. `app.get('/health', (req, res) => res.json({ok:true}))`
 * in Flask/FastAPI) — otherwise that service will always log as unreachable
 * even when it's actually fine.
 */
async function checkMicroservices() {
  const services = [
    { name: 'Detection (ML/NLP + blockchain)', url: process.env.DETECTION_SERVICE_URL },
    { name: 'Forensics (SPF/DKIM/DMARC)', url: process.env.FORENSICS_SERVICE_URL },
    { name: 'Enrichment (GeoIP/WHOIS)', url: process.env.ENRICHMENT_SERVICE_URL }
  ];

  console.log('\nChecking microservice connectivity...');

  for (const svc of services) {
    if (!svc.url) {
      console.log(`  ⚠️  ${svc.name}: no URL set in .env — skipping`);
      continue;
    }
    try {
      await axios.get(`${svc.url}/health`, { timeout: 4000 });
      console.log(`  ✅ ${svc.name} reachable (${svc.url})`);
    } catch (err) {
      const reason = err.code === 'ECONNABORTED' ? 'timed out' : err.code || err.message;
      console.log(`  ❌ ${svc.name} NOT reachable (${svc.url}) — ${reason}`);
    }
  }
  console.log(''); // blank line to separate from the rest of startup logs
}

module.exports = checkMicroservices;