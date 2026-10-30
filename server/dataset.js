/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: dataset.js
 * 
 * Reproducible, synthetic labeled evaluation dataset generator.
 * Generates 'normal' and 'simulated_covert' DNS query samples with comprehensive
 * network features and scenario-based grouping to prevent evaluation leakage.
 * 
 * DISCLAIMER:
 * Generated datasets are synthetic and designed exclusively for controlled,
 * reproducible academic experiments. They do not claim to represent all real-world traffic.
 */

const { processEncodingPipeline, encodeMessage } = require('./encoder');
const { calculateShannonEntropy, calculateUnusualCharRatio, parseDomainParts } = require('./detector');

/**
 * Fast, deterministic 32-bit PRNG (Mulberry32).
 * @param {number|string} seed
 * @returns {() => number} Returns float in [0, 1)
 */
function createPrng(seed) {
  let s = 0x12345678;
  if (typeof seed === 'number' && !isNaN(seed)) {
    s = seed >>> 0;
  } else if (typeof seed === 'string') {
    for (let i = 0; i < seed.length; i++) {
      s = (Math.imul(31, s) + seed.charCodeAt(i)) >>> 0;
    }
  }
  if (s === 0) s = 0x12345678;

  return function nextRandom() {
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Curated realistic benign domain templates across multiple enterprise/academic profiles
const NORMAL_TEMPLATES = [
  // 1. Popular Web & Search
  { base: 'google.com', subdomains: ['www', 'mail', 'drive', 'docs', 'maps', 'accounts', 'myaccount'] },
  { base: 'wikipedia.org', subdomains: ['en', 'fr', 'de', 'es', 'upload', 'commons', 'meta'] },
  { base: 'github.com', subdomains: ['api', 'gist', 'raw', 'status', 'assets-cdn', 'support'] },
  { base: 'microsoft.com', subdomains: ['support', 'account', 'login', 'portal', 'azure', 'teams'] },
  // 2. CDNs & Cloud Infrastructure (Naturally elevated length/entropy in real-world DNS)
  { base: 'cloudfront.net', subdomains: ['d1v78abx9z', 'd2z99x11qw', 'd3k82m04aa', 'd4p77k91op'] },
  { base: 'akamaized.net', subdomains: ['img-prod-cms-rt', 'media-cache-ec0', 'static-assets-prd'] },
  { base: 'cloudflare.net', subdomains: ['cdn', 'assets', 'static', 'pkg-repo-v2', 'edge-gateway'] },
  // 3. Telemetry & Analytics (Legitimate high-entropy / UUID labels)
  { base: 'office.com', subdomains: ['telemetry-01.prod', 'client-metrics.prod', 'telemetry-service'] },
  { base: 'digicert.com', subdomains: ['ocsp', 'crl3', 'crl4', 'status'] },
  // 4. Enterprise Internal Namespaces & Service Discovery
  { base: 'corp.local', subdomains: ['_ldap._tcp.dc._msdcs', 'auth-service.prod', 'db-primary.lan'] },
  { base: 'cluster.local', subdomains: ['kube-dns.kube-system.svc', 'metrics-server.monitoring.svc'] }
];

// Curated covert secret payloads for diverse encoding scenarios
const COVERT_MESSAGES = [
  'COMPUTER NETWORKS PROJECT',
  'SECRET_KEY_EXFILTRATION_TEST',
  'PAYLOAD_BURST_COVERT_CHANNEL',
  'DEFENSE_EVALUATION_SAMPLE',
  'TOP_SECRET_SESSION_TOKEN_9981',
  'NETWORK_FORENSICS_LAB_DATA',
  'DNS_TUNNEL_TEST_FRAMEWORK',
  'USER_CREDENTIAL_SIMULATION_HASH'
];

// A covert channel only works if the queries reach a nameserver the *receiver* controls,
// so simulated covert traffic targets RFC 2606 reserved example domains (never real brands).
const COVERT_TARGET_DOMAINS = ['example.com', 'example.net', 'example.org', 'tunnel.example', 'lab.example'];
const SUPPORTED_ENCODINGS = ['base64', 'hex', 'binary', 'base32'];

/**
 * Extracts standard evaluation features from a DNS query name.
 * @param {string} queryName
 * @param {number} qps
 * @returns {Object}
 */
function extractQueryFeatures(queryName, qps = 1.0) {
  const { subdomain, baseDomain } = parseDomainParts(queryName);
  const labels = subdomain ? subdomain.split('.') : [];
  const longestSubdomainLength = labels.length > 0 
    ? Math.max(...labels.map(l => l.length)) 
    : 0;

  const entropy = calculateShannonEntropy(subdomain || queryName);
  // Use original case so uppercase payload characters are counted (matches detector.js)
  const originalTrimmed = String(queryName).trim().replace(/^\.+|\.+$/g, '');
  const originalSubdomain = subdomain ? originalTrimmed.slice(0, subdomain.length) : '';
  const unusualCharRatio = calculateUnusualCharRatio(originalSubdomain || originalTrimmed);
  const payloadToDomainRatio = baseDomain.length > 0
    ? Number((subdomain.length / baseDomain.length).toFixed(2))
    : 0;

  return {
    queryLength: queryName.length,
    subdomainLength: subdomain.length,
    longestSubdomainLength,
    entropy,
    unusualCharRatio,
    payloadToDomainRatio,
    queryFrequency: Number(qps.toFixed(2))
  };
}

/**
 * Generates a balanced, labeled dataset with scenario-level metadata.
 * 
 * @param {Object} options
 * @param {number} [options.sampleCount=100] - Total samples desired (min: 10, max: 2000)
 * @param {number|string} [options.seed=42] - Seed for reproducibility
 * @param {number} [options.normalRatio=0.5] - Ratio of normal samples (0.1 - 0.9)
 * @param {string} [options.encoding='all'] - 'all' or one of 'base64', 'hex', 'binary', 'base32'
 * @param {number} [options.packetLoss=0] - Packet loss percentage for covert streams (0 - 50)
 * @returns {Object} { samples, metadata }
 */
function generateLabeledDataset(options = {}) {
  const sampleCount = Math.max(10, Math.min(2000, parseInt(options.sampleCount, 10) || 100));
  const rawSeed = options.seed !== undefined ? options.seed : 42;
  const prng = createPrng(rawSeed);

  const normalRatio = Math.max(0.1, Math.min(0.9, parseFloat(options.normalRatio) || 0.5));
  const targetNormalCount = Math.round(sampleCount * normalRatio);
  const targetCovertCount = sampleCount - targetNormalCount;

  const encodingFilter = options.encoding && options.encoding !== 'all' 
    ? options.encoding.toLowerCase() 
    : 'all';

  const packetLoss = Math.max(0, Math.min(50, parseInt(options.packetLoss, 10) || 0));

  const samples = [];
  let sampleIndex = 1;

  // -------------------------------------------------------------
  // 1. Generate Normal Traffic Samples (Organized in Scenarios)
  // -------------------------------------------------------------
  let generatedNormal = 0;
  let normalScenarioIdx = 1;

  while (generatedNormal < targetNormalCount) {
    const scenarioId = `SCN-NORM-${String(normalScenarioIdx).padStart(3, '0')}`;
    normalScenarioIdx++;

    // Pick a template domain
    const template = NORMAL_TEMPLATES[Math.floor(prng() * NORMAL_TEMPLATES.length)];
    const scenarioQps = 0.5 + prng() * 4.5; // 0.5 - 5.0 QPS
    const scenarioSize = Math.min(targetNormalCount - generatedNormal, 3 + Math.floor(prng() * 5));

    for (let k = 0; k < scenarioSize; k++) {
      const sub = template.subdomains[Math.floor(prng() * template.subdomains.length)];
      let fqdn = `${sub}.${template.base}`;

      // Occasionally append dynamic parameters (e.g. cache buster, token, or session ID)
      const variantRoll = prng();
      if (variantRoll < 0.25) {
        // Alphanumeric hash or UUID snippet (tests realistic false-positive tolerance)
        const hash = Math.floor(prng() * 1e8).toString(16);
        fqdn = `node-${hash}.${sub}.${template.base}`;
      } else if (variantRoll < 0.40) {
        // Multi-level service label
        fqdn = `srv${k + 1}.${sub}.${template.base}`;
      }

      const features = extractQueryFeatures(fqdn, scenarioQps);

      samples.push({
        sampleId: `SMPL-${String(sampleIndex++).padStart(5, '0')}`,
        scenarioId,
        label: 'normal',
        queryName: fqdn,
        ...features,
        encodingMethod: 'none',
        deliveryStatus: 'DELIVERED', // Normal queries are recorded traffic
        randomSeed: rawSeed
      });

      generatedNormal++;
      if (generatedNormal >= targetNormalCount) break;
    }
  }

  // -------------------------------------------------------------
  // 2. Generate Simulated Covert Samples (Organized in Scenarios)
  // -------------------------------------------------------------
  let generatedCovert = 0;
  let covertScenarioIdx = 1;

  while (generatedCovert < targetCovertCount) {
    const scenarioId = `SCN-COV-${String(covertScenarioIdx).padStart(3, '0')}`;
    covertScenarioIdx++;

    const method = encodingFilter === 'all'
      ? SUPPORTED_ENCODINGS[Math.floor(prng() * SUPPORTED_ENCODINGS.length)]
      : encodingFilter;

    const baseMessage = COVERT_MESSAGES[Math.floor(prng() * COVERT_MESSAGES.length)];
    const message = `${baseMessage} ${Math.floor(prng() * 1000)}`;
    const baseDomain = COVERT_TARGET_DOMAINS[Math.floor(prng() * COVERT_TARGET_DOMAINS.length)];
    const chunkSize = 8 + Math.floor(prng() * 16); // 8 - 24 chars
    const scenarioQps = 1.0 + prng() * 9.0; // 1.0 - 10.0 QPS

    const pipeline = processEncodingPipeline(message, method, chunkSize, baseDomain, true);
    const chunks = pipeline.chunks || [];

    for (let c = 0; c < chunks.length; c++) {
      const queryName = chunks[c].queryName;
      const features = extractQueryFeatures(queryName, scenarioQps);

      // Packet loss simulation on transmission:
      // Note: Ground-truth remains 'simulated_covert'. Packet loss affects delivery only!
      const isLost = packetLoss > 0 && (prng() * 100 < packetLoss);
      const deliveryStatus = isLost ? 'LOST' : 'DELIVERED';

      samples.push({
        sampleId: `SMPL-${String(sampleIndex++).padStart(5, '0')}`,
        scenarioId,
        label: 'simulated_covert',
        queryName,
        ...features,
        encodingMethod: method,
        deliveryStatus,
        randomSeed: rawSeed
      });

      generatedCovert++;
      if (generatedCovert >= targetCovertCount) break;
    }
  }

  return {
    metadata: {
      totalSamples: samples.length,
      normalCount: generatedNormal,
      covertCount: generatedCovert,
      seed: rawSeed,
      encoding: encodingFilter,
      packetLoss,
      isSyntheticEvaluationData: true,
      notice: 'SYNTHETIC EXPERIMENTAL DATA — NOT EXTERNAL LIVE INTERNET TRAFFIC'
    },
    samples
  };
}

/**
 * Splits a dataset into Calibration and Evaluation sets GROUPED BY SCENARIO.
 * Prevents evaluation leakage by ensuring no scenario is split across both sets.
 * 
 * @param {Array<Object>} samples - Full dataset of samples
 * @param {number} [splitRatio=0.3] - Fraction of scenarios allocated to calibration (0.1 - 0.5)
 * @param {number|string} [seed=42] - Seed for deterministic partition
 * @returns {Object} { calibrationSet, evaluationSet, stats }
 */
function splitDatasetByScenario(samples, splitRatio = 0.3, seed = 42) {
  if (!Array.isArray(samples) || samples.length === 0) {
    return {
      calibrationSet: [],
      evaluationSet: [],
      stats: { calibrationTotal: 0, evaluationTotal: 0, calibrationScenarios: 0, evaluationScenarios: 0 }
    };
  }

  const ratio = Math.max(0.1, Math.min(0.7, parseFloat(splitRatio) || 0.3));
  const prng = createPrng(seed);

  // Group samples by scenarioId
  const scenariosMap = new Map();
  for (const sample of samples) {
    const scn = sample.scenarioId || 'DEFAULT';
    if (!scenariosMap.has(scn)) {
      scenariosMap.set(scn, []);
    }
    scenariosMap.get(scn).push(sample);
  }

  const scenarioIds = Array.from(scenariosMap.keys());

  // STRATIFIED scenario split: each scenario carries a single label, so scenarios
  // are grouped by label and each class is split separately. This guarantees both
  // classes appear in the calibration set AND the evaluation set (an unstratified
  // split could leave calibration with only covert samples, which collapses the
  // entropy threshold) while still keeping whole scenarios on one side (no leakage).
  const totalSamples = samples.length;
  const byLabel = new Map();
  for (const scnId of scenarioIds) {
    const label = scenariosMap.get(scnId)[0].label || 'unknown';
    if (!byLabel.has(label)) byLabel.set(label, []);
    byLabel.get(label).push(scnId);
  }

  const calibrationScenarios = new Set();
  const evaluationScenarios = new Set();

  for (const label of Array.from(byLabel.keys()).sort()) {
    const ids = byLabel.get(label);
    // Deterministic Fisher-Yates shuffle within the class
    for (let i = ids.length - 1; i > 0; i--) {
      const j = Math.floor(prng() * (i + 1));
      [ids[i], ids[j]] = [ids[j], ids[i]];
    }
    const classTotal = ids.reduce((n, id) => n + scenariosMap.get(id).length, 0);
    const target = Math.round(classTotal * ratio);
    let calCount = 0;
    const calIds = [];
    const evalIds = [];
    for (const id of ids) {
      const n = scenariosMap.get(id).length;
      if (calIds.length === 0 || calCount + n <= target) {
        calIds.push(id);
        calCount += n;
      } else {
        evalIds.push(id);
      }
    }
    // Keep at least one scenario of this class in evaluation when possible
    if (evalIds.length === 0 && calIds.length > 1) evalIds.push(calIds.pop());
    calIds.forEach(id => calibrationScenarios.add(id));
    evalIds.forEach(id => evaluationScenarios.add(id));
  }

  const calibrationSet = [];
  const evaluationSet = [];

  for (const sample of samples) {
    if (calibrationScenarios.has(sample.scenarioId)) {
      calibrationSet.push(sample);
    } else {
      evaluationSet.push(sample);
    }
  }

  return {
    calibrationSet,
    evaluationSet,
    stats: {
      totalSamples,
      calibrationTotal: calibrationSet.length,
      evaluationTotal: evaluationSet.length,
      calibrationScenarios: calibrationScenarios.size,
      evaluationScenarios: evaluationScenarios.size,
      calibrationNormal: calibrationSet.filter(s => s.label === 'normal').length,
      calibrationCovert: calibrationSet.filter(s => s.label === 'simulated_covert').length,
      evaluationNormal: evaluationSet.filter(s => s.label === 'normal').length,
      evaluationCovert: evaluationSet.filter(s => s.label === 'simulated_covert').length,
      scenarioLeakageDetected: false
    }
  };
}

module.exports = {
  createPrng,
  extractQueryFeatures,
  generateLabeledDataset,
  splitDatasetByScenario,
  NORMAL_TEMPLATES,
  COVERT_MESSAGES
};
