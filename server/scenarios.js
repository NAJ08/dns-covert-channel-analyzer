/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: scenarios.js
 * 
 * Generates synthetic, multi-client DNS traffic streams for interactive replay,
 * network topology visualization, security investigation, and scenario-based evaluation.
 * 
 * DISCLAIMER:
 * All events, hostnames, IP addresses, and packets are 100% synthetic local models.
 * No packets are transmitted to or captured from real networks.
 */

const { createPrng, NORMAL_TEMPLATES } = require('./dataset');
const { createSimulatedPacket } = require('./simulator');
const { 
  analyzeSingleQuery, 
  calculateShannonEntropy, 
  calculateUnusualCharRatio, 
  parseDomainParts 
} = require('./detector');
const { encodeMessage } = require('./encoder');
const { reconstructMessage } = require('./decoder');

// Synthetic Network Topology Nodes
const TOPOLOGY_CLIENTS = [
  {
    id: 'client-01',
    name: 'Workstation-01 (Finance)',
    ip: '192.168.1.101',
    mac: '02:00:5E:01:01:01',
    type: 'Workstation',
    os: 'Windows 11 Enterprise',
    role: 'Employee Desktop'
  },
  {
    id: 'client-02',
    name: 'Laptop-02 (Engineering)',
    ip: '192.168.1.102',
    mac: '02:00:5E:01:01:02',
    type: 'Laptop',
    os: 'Ubuntu 22.04 LTS',
    role: 'Developer Host'
  },
  {
    id: 'client-03',
    name: 'IoT-Sensor-03 (HVAC/Cam)',
    ip: '192.168.1.103',
    mac: '02:00:5E:01:01:03',
    type: 'IoT',
    os: 'Embedded Linux',
    role: 'Building Automation'
  }
];

const TOPOLOGY_RESOLVER = {
  id: 'resolver-01',
  name: 'Local DNS Gateway & Resolver',
  ip: '192.168.1.1',
  forwarderIp: '8.8.8.8',
  role: 'Recursive Caching Resolver'
};

const TOPOLOGY_DESTINATIONS = {
  web: {
    id: 'dest-web',
    name: 'Public Web DNS',
    ip: '198.51.100.10',
    domains: ['google.com', 'wikipedia.org', 'github.com', 'microsoft.com']
  },
  cdn: {
    id: 'dest-cdn',
    name: 'Edge CDN DNS',
    ip: '198.51.100.20',
    domains: ['cloudfront.net', 'akamaized.net', 'cloudflare.net']
  },
  corp: {
    id: 'dest-corp',
    name: 'Internal AD Nameserver',
    ip: '10.0.0.53',
    domains: ['corp.local', 'cluster.local']
  },
  covert: {
    id: 'dest-covert',
    name: 'Simulated Attacker Nameserver',
    ip: '203.0.113.99',
    domains: ['google.com', 'cloudflare.com', 'microsoft.com']
  }
};

const PREDEFINED_SCENARIOS = {
  normal_browsing: {
    id: 'normal_browsing',
    title: '1. Normal DNS Browsing',
    badge: 'Baseline Benign',
    badgeClass: 'badge-normal',
    description: 'Typical enterprise day-to-day traffic across three internal clients. Queries follow natural language conventions with low character entropy and standard subdomain lengths.',
    eventCount: 24,
    expectedAnomalyRatio: '0%'
  },
  query_burst: {
    id: 'query_burst',
    title: '2. Unusual Query Burst',
    badge: 'Rate Anomaly',
    badgeClass: 'badge-unusual',
    description: 'An infected or misconfigured IoT sensor suddenly generates an aggressive burst of DNS lookups in rapid succession (high QPS), simulating automated beaconing or reconnaissance.',
    eventCount: 26,
    expectedAnomalyRatio: '30-40%'
  },
  high_entropy: {
    id: 'high_entropy',
    title: '3. High-Entropy DNS Labels',
    badge: 'Covert Stego',
    badgeClass: 'badge-suspicious',
    description: 'A compromised laptop exfiltrates encoded secrets embedded inside Base64 and Base32 subdomains, exhibiting character entropy exceeding 3.8 bits/char.',
    eventCount: 26,
    expectedAnomalyRatio: '40-50%'
  },
  long_queries: {
    id: 'long_queries',
    title: '4. Long Query Names',
    badge: 'Structure Anomaly',
    badgeClass: 'badge-suspicious',
    description: 'Covert tunneling maximizing bandwidth by packing large chunks near RFC 1035 label boundaries (up to 55+ characters), drastically inflating the payload-to-domain ratio.',
    eventCount: 24,
    expectedAnomalyRatio: '45-55%'
  },
  mixed_traffic: {
    id: 'mixed_traffic',
    title: '5. Mixed Normal & Anomalous Traffic',
    badge: 'SOC Investigation',
    badgeClass: 'badge-danger',
    description: 'A realistic SOC scenario where stealthy data exfiltration is blended into background traffic containing legitimate high-entropy CDN hashes, challenging analyst triage.',
    eventCount: 32,
    expectedAnomalyRatio: '25-35%'
  },
  packet_loss_reconstruction: {
    id: 'packet_loss_reconstruction',
    title: '6. Packet-Loss & Reconstruction',
    badge: 'Transport Loss',
    badgeClass: 'badge-unusual',
    description: 'A multi-packet covert channel transmission subject to 20% UDP packet loss. Demonstrates dropped datagrams, missing sequence IDs, and reconstruction failure while evaluating anomaly detection independently.',
    eventCount: 24,
    expectedAnomalyRatio: '50-60%'
  }
};

/**
 * Returns scenario definitions for UI dropdowns.
 */
function getScenarioList() {
  return Object.values(PREDEFINED_SCENARIOS);
}

/**
 * Generates an event stream for the specified scenario.
 * @param {Object} options
 * @param {string} options.scenarioId - Scenario key
 * @param {number} options.seed - Deterministic PRNG seed
 * @param {number} [options.packetLoss] - Optional packet loss override (0-30%)
 * @returns {Object} Complete replay scenario stream
 */
function generateScenarioStream({
  scenarioId = 'normal_browsing',
  seed = 42,
  packetLoss = 0
}) {
  const scenarioDef = PREDEFINED_SCENARIOS[scenarioId] || PREDEFINED_SCENARIOS['normal_browsing'];
  const rng = createPrng(seed);

  // Time generator starting at a realistic morning timestamp: 09:15:00
  let currentMillis = 9 * 3600 * 1000 + 15 * 60 * 1000;
  function formatTimestamp(ms) {
    const totalSec = Math.floor(ms / 1000);
    const msec = ms % 1000;
    const hours = Math.floor(totalSec / 3600) % 24;
    const minutes = Math.floor((totalSec % 3600) / 60);
    const seconds = totalSec % 60;
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${String(msec).padStart(3, '0')}`;
  }

  const events = [];
  const totalEvents = scenarioDef.eventCount;

  // Helper to pick from an array with deterministic PRNG
  function pick(arr) {
    return arr[Math.floor(rng() * arr.length)];
  }

  // Helper to create a benign normal query
  function createNormalQuery() {
    const tmpl = pick(NORMAL_TEMPLATES);
    const sub = pick(tmpl.subdomains);
    return `${sub}.${tmpl.base}`;
  }

  // Helper to construct an event object
  function buildEvent({
    index,
    client,
    destType,
    queryName,
    groundTruth,
    delayMs,
    qps = 1.0,
    isBurst = false,
    deliveryStatus = 'DELIVERED',
    packetNumber = index + 1,
    chunk = ''
  }) {
    currentMillis += delayMs;
    const timestampStr = formatTimestamp(currentMillis);
    const { subdomain, baseDomain } = parseDomainParts(queryName);
    const labels = subdomain ? subdomain.split('.') : [];
    const longestSubdomainLength = labels.length > 0 ? Math.max(...labels.map(l => l.length)) : 0;
    const entropy = calculateShannonEntropy(subdomain || queryName);
    const unusualCharRatio = calculateUnusualCharRatio(subdomain || queryName);
    const payloadToDomainRatio = baseDomain.length > 0
      ? Number((subdomain.length / baseDomain.length).toFixed(2))
      : 0;

    // Run existing detector
    const analysis = analyzeSingleQuery({
      queryName,
      queryType: 'A',
      timestamp: timestampStr,
      packetNumber
    });

    // Destination node determination
    let destNode = TOPOLOGY_DESTINATIONS.web;
    if (destType === 'cdn') destNode = TOPOLOGY_DESTINATIONS.cdn;
    else if (destType === 'corp') destNode = TOPOLOGY_DESTINATIONS.corp;
    else if (destType === 'covert' || groundTruth === 'simulated_covert') destNode = TOPOLOGY_DESTINATIONS.covert;

    // Create full RFC 1035 simulated packet model
    const packet = createSimulatedPacket({
      packetNumber,
      totalPackets: totalEvents,
      queryName,
      encodedPayload: chunk,
      queryType: 'A',
      timestamp: new Date(Date.UTC(2026, 9, 19, 9, 15, 0, currentMillis)),
      delayMs,
      deliveryStatus,
      baseDomain
    });

    return {
      id: `EVT-${String(index + 1).padStart(3, '0')}`,
      eventIndex: index,
      timestamp: timestampStr,
      timestampMs: currentMillis,
      client: {
        id: client.id,
        name: client.name,
        ip: client.ip,
        type: client.type,
        role: client.role
      },
      resolver: TOPOLOGY_RESOLVER,
      destination: {
        id: destNode.id,
        name: destNode.name,
        ip: destNode.ip,
        domain: baseDomain
      },
      queryName,
      queryType: 'A',
      groundTruth, // 'normal' or 'simulated_covert'
      deliveryStatus, // 'DELIVERED' or 'LOST'
      packetNumber,
      interArrivalMs: delayMs,
      features: {
        queryLength: queryName.length,
        subdomainLength: subdomain.length,
        longestSubdomainLength,
        entropy,
        unusualCharRatio,
        payloadToDomainRatio,
        queryFrequency: Number(qps.toFixed(2)),
        isBurst
      },
      analysis: {
        score: analysis.score,
        status: analysis.status, // 'Normal', 'Unusual', 'Suspicious'
        predicted: analysis.score >= 50 ? 'simulated_covert' : 'normal',
        reasons: analysis.reasons,
        isBinarySignature: analysis.isBinarySignature
      },
      packet
    };
  }

  // Generate according to scenario
  switch (scenarioId) {
    case 'normal_browsing': {
      for (let i = 0; i < totalEvents; i++) {
        const client = TOPOLOGY_CLIENTS[i % TOPOLOGY_CLIENTS.length];
        const queryName = createNormalQuery();
        const isCorp = queryName.includes('.local');
        const isCdn = queryName.includes('cloudfront') || queryName.includes('akamai');
        const destType = isCorp ? 'corp' : (isCdn ? 'cdn' : 'web');
        const delayMs = Math.floor(700 + rng() * 1200); // 700ms - 1900ms

        events.push(buildEvent({
          index: i,
          client,
          destType,
          queryName,
          groundTruth: 'normal',
          delayMs,
          qps: Number((1000 / delayMs).toFixed(2))
        }));
      }
      break;
    }

    case 'query_burst': {
      // First 8 events: normal browsing
      for (let i = 0; i < 8; i++) {
        const client = TOPOLOGY_CLIENTS[i % 2]; // client-01 and client-02
        const delayMs = Math.floor(800 + rng() * 800);
        events.push(buildEvent({
          index: i,
          client,
          destType: 'web',
          queryName: createNormalQuery(),
          groundTruth: 'normal',
          delayMs,
          qps: 1.2
        }));
      }

      // Next 12 events: Sudden automated high-rate burst from IoT Sensor (client-03)
      const burstDomains = ['telemetry-sync-api.iot-cloud.org', 'firmware-beacon.dev-lan.net', 'ping-collector-srv01.io'];
      for (let i = 8; i < 20; i++) {
        const targetDomain = burstDomains[(i - 8) % burstDomains.length];
        const burstQuery = `node-${i - 7}.${targetDomain}`;
        const delayMs = Math.floor(35 + rng() * 45); // 35ms - 80ms (High QPS: 15-25 QPS!)
        events.push(buildEvent({
          index: i,
          client: TOPOLOGY_CLIENTS[2], // client-03 (IoT)
          destType: 'web',
          queryName: burstQuery,
          groundTruth: 'simulated_covert',
          delayMs,
          qps: Number((1000 / delayMs).toFixed(1)),
          isBurst: true
        }));
      }

      // Final events: Return to normal browsing
      for (let i = 20; i < totalEvents; i++) {
        const client = TOPOLOGY_CLIENTS[i % 2];
        const delayMs = Math.floor(900 + rng() * 800);
        events.push(buildEvent({
          index: i,
          client,
          destType: 'web',
          queryName: createNormalQuery(),
          groundTruth: 'normal',
          delayMs,
          qps: 1.0
        }));
      }
      break;
    }

    case 'high_entropy': {
      const secret = 'TOP_SECRET_FINANCIAL_LEDGER_2026';
      const encoded = encodeMessage(secret, 'base64');
      // Split into 8-character covert chunks
      const chunks = encoded.match(/.{1,8}/g) || [encoded];

      let covertIdx = 0;
      for (let i = 0; i < totalEvents; i++) {
        const isCovert = (i >= 4 && i < 4 + chunks.length * 2 && i % 2 === 0);
        if (isCovert && covertIdx < chunks.length) {
          const chunk = chunks[covertIdx];
          const queryName = `pkt${String(covertIdx + 1).padStart(2, '0')}-${chunk}.cloudflare.com`;
          const delayMs = Math.floor(400 + rng() * 300);
          events.push(buildEvent({
            index: i,
            client: TOPOLOGY_CLIENTS[1], // client-02 (Laptop)
            destType: 'covert',
            queryName,
            groundTruth: 'simulated_covert',
            delayMs,
            qps: 2.5,
            packetNumber: covertIdx + 1,
            chunk
          }));
          covertIdx++;
        } else {
          const client = TOPOLOGY_CLIENTS[i % TOPOLOGY_CLIENTS.length];
          const delayMs = Math.floor(600 + rng() * 900);
          events.push(buildEvent({
            index: i,
            client,
            destType: 'web',
            queryName: createNormalQuery(),
            groundTruth: 'normal',
            delayMs,
            qps: 1.2
          }));
        }
      }
      break;
    }

    case 'long_queries': {
      // Long queries pushing label boundaries (e.g. Hex encoding with 40-56 char subdomains)
      const secretHex = encodeMessage('CREDENTIALS_DATABASE_DUMP_SYSADMIN', 'hex');
      const longChunks = secretHex.match(/.{1,44}/g) || [secretHex];

      let chunkIdx = 0;
      for (let i = 0; i < totalEvents; i++) {
        const isLong = (i >= 3 && i < 3 + longChunks.length * 2 && i % 2 === 1);
        if (isLong && chunkIdx < longChunks.length) {
          const chunk = longChunks[chunkIdx];
          const queryName = `data-seq${chunkIdx + 1}-${chunk}.example.com`;
          const delayMs = Math.floor(350 + rng() * 350);
          events.push(buildEvent({
            index: i,
            client: TOPOLOGY_CLIENTS[0], // client-01 (Workstation)
            destType: 'covert',
            queryName,
            groundTruth: 'simulated_covert',
            delayMs,
            qps: 2.8,
            packetNumber: chunkIdx + 1,
            chunk
          }));
          chunkIdx++;
        } else {
          const client = TOPOLOGY_CLIENTS[i % TOPOLOGY_CLIENTS.length];
          const delayMs = Math.floor(600 + rng() * 800);
          events.push(buildEvent({
            index: i,
            client,
            destType: 'web',
            queryName: createNormalQuery(),
            groundTruth: 'normal',
            delayMs,
            qps: 1.1
          }));
        }
      }
      break;
    }

    case 'mixed_traffic': {
      // Realistic blend: ~70% benign (including CDN hashes), ~30% covert
      const covertSecret = 'C2_AUTH_TOKEN_BEACON_4991';
      const covertChunks = encodeMessage(covertSecret, 'base32').match(/.{1,10}/g) || ['JZCVIV2PKJ'];
      let covertPtr = 0;

      for (let i = 0; i < totalEvents; i++) {
        // Interleave covert events around every 3-4 packets
        const isCovertTurn = (i % 4 === 1) && (covertPtr < covertChunks.length);
        if (isCovertTurn) {
          const chunk = covertChunks[covertPtr];
          const queryName = `auth-ch${covertPtr + 1}-${chunk}.microsoft.com`;
          const delayMs = Math.floor(450 + rng() * 300);
          events.push(buildEvent({
            index: i,
            client: TOPOLOGY_CLIENTS[1], // client-02 is the covert actor
            destType: 'covert',
            queryName,
            groundTruth: 'simulated_covert',
            delayMs,
            qps: 2.2,
            packetNumber: covertPtr + 1,
            chunk
          }));
          covertPtr++;
        } else {
          const client = TOPOLOGY_CLIENTS[i % TOPOLOGY_CLIENTS.length];
          const queryName = createNormalQuery();
          const isCdn = queryName.includes('cloudfront') || queryName.includes('akamai');
          const destType = isCdn ? 'cdn' : 'web';
          const delayMs = Math.floor(650 + rng() * 850);
          events.push(buildEvent({
            index: i,
            client,
            destType,
            queryName,
            groundTruth: 'normal',
            delayMs,
            qps: 1.3
          }));
        }
      }
      break;
    }

    case 'packet_loss_reconstruction': {
      // 10-packet covert transmission with simulated packet drop
      const lossRate = packetLoss > 0 ? packetLoss / 100 : 0.20; // 20% loss default
      const message = 'RESILIENT_UDP_COVERT_CHANNEL_DEMO';
      const b64 = encodeMessage(message, 'base64');
      const chunks = b64.match(/.{1,8}/g) || [b64];

      const droppedSeqSet = new Set();
      // Drop ~20% of covert chunks
      for (let c = 0; c < chunks.length; c++) {
        if (rng() < lossRate && droppedSeqSet.size < Math.ceil(chunks.length * 0.3)) {
          droppedSeqSet.add(c + 1);
        }
      }
      if (droppedSeqSet.size === 0 && chunks.length > 3) {
        droppedSeqSet.add(3); // ensure at least one drop for clear educational demonstration
      }

      let chunkIdx = 0;
      for (let i = 0; i < totalEvents; i++) {
        const isCovert = (i % 2 === 1 && chunkIdx < chunks.length);
        if (isCovert) {
          const seq = chunkIdx + 1;
          const chunk = chunks[chunkIdx];
          const queryName = `pkt${String(seq).padStart(2, '0')}-${chunk}.example.com`;
          const isLost = droppedSeqSet.has(seq);
          const delayMs = Math.floor(350 + rng() * 250);

          events.push(buildEvent({
            index: i,
            client: TOPOLOGY_CLIENTS[0], // client-01
            destType: 'covert',
            queryName,
            groundTruth: 'simulated_covert',
            deliveryStatus: isLost ? 'LOST' : 'DELIVERED',
            delayMs,
            qps: 2.7,
            packetNumber: seq,
            chunk
          }));
          chunkIdx++;
        } else {
          const client = TOPOLOGY_CLIENTS[i % TOPOLOGY_CLIENTS.length];
          const delayMs = Math.floor(700 + rng() * 700);
          events.push(buildEvent({
            index: i,
            client,
            destType: 'web',
            queryName: createNormalQuery(),
            groundTruth: 'normal',
            delayMs,
            qps: 1.2
          }));
        }
      }
      break;
    }
  }

  // Summary statistics
  const totalCount = events.length;
  const normalCount = events.filter(e => e.groundTruth === 'normal').length;
  const covertCount = events.filter(e => e.groundTruth === 'simulated_covert').length;
  const suspiciousCount = events.filter(e => e.analysis.status === 'Suspicious').length;
  const unusualCount = events.filter(e => e.analysis.status === 'Unusual').length;
  const lostCount = events.filter(e => e.deliveryStatus === 'LOST').length;

  return {
    scenario: scenarioDef,
    seed,
    topology: {
      clients: TOPOLOGY_CLIENTS,
      resolver: TOPOLOGY_RESOLVER,
      destinations: Object.values(TOPOLOGY_DESTINATIONS)
    },
    summary: {
      totalEvents: totalCount,
      normalCount,
      covertCount,
      suspiciousCount,
      unusualCount,
      lostCount,
      totalDurationMs: currentMillis - (9 * 3600 * 1000 + 15 * 60 * 1000)
    },
    events
  };
}

module.exports = {
  PREDEFINED_SCENARIOS,
  TOPOLOGY_CLIENTS,
  TOPOLOGY_RESOLVER,
  TOPOLOGY_DESTINATIONS,
  getScenarioList,
  generateScenarioStream
};
