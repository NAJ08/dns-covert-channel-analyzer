/**
 * Automated Tests for Synthetic DNS Traffic Scenarios & Investigation Replay
 */

const assert = require('assert');
const http = require('http');
const { 
  getScenarioList, 
  generateScenarioStream, 
  PREDEFINED_SCENARIOS,
  TOPOLOGY_CLIENTS 
} = require('../server/scenarios');
const app = require('../server/server');

console.log('--- Starting Synthetic Traffic Scenarios & Replay Tests ---');

// Test 1: Scenario list returns all 6 predefined scenarios
const list = getScenarioList();
assert(Array.isArray(list) && list.length === 6, 'Scenario list must contain 6 scenarios');
const scenarioKeys = ['normal_browsing', 'query_burst', 'high_entropy', 'long_queries', 'mixed_traffic', 'packet_loss_reconstruction'];
scenarioKeys.forEach(key => {
  assert(list.some(s => s.id === key), `Scenario list must include ${key}`);
});
console.log('[PASS] Scenario list correctly defines all 6 predefined investigation scenarios');

// Test 2: Seed determinism in scenario generation
const streamA = generateScenarioStream({ scenarioId: 'mixed_traffic', seed: 1234 });
const streamB = generateScenarioStream({ scenarioId: 'mixed_traffic', seed: 1234 });
assert.strictEqual(streamA.events.length, streamB.events.length, 'Same seed must generate identical event counts');
for (let i = 0; i < streamA.events.length; i++) {
  assert.strictEqual(streamA.events[i].queryName, streamB.events[i].queryName, `Event ${i} queryName mismatch`);
  assert.strictEqual(streamA.events[i].client.id, streamB.events[i].client.id, `Event ${i} client ID mismatch`);
}
console.log('[PASS] Scenario generation is strictly deterministic with random seed');

// Test 3: Normal browsing scenario contains only normal ground-truth
const normStream = generateScenarioStream({ scenarioId: 'normal_browsing', seed: 42 });
assert(normStream.events.length >= 20, 'Normal browsing should have >= 20 events');
assert(normStream.events.every(e => e.groundTruth === 'normal'), 'All events in normal browsing must have groundTruth normal');
assert(normStream.summary.normalCount === normStream.events.length, 'Summary normalCount should match event length');
console.log('[PASS] Normal browsing scenario generates exclusively normal background traffic');

// Test 4: Query burst scenario has high QPS / burst flags
const burstStream = generateScenarioStream({ scenarioId: 'query_burst', seed: 42 });
const burstEvents = burstStream.events.filter(e => e.features.isBurst);
assert(burstEvents.length > 0, 'Query burst scenario must contain burst events');
assert(burstEvents.every(e => e.client.id === 'client-03'), 'Burst events must originate from IoT sensor (client-03)');
assert(burstEvents.every(e => e.features.queryFrequency > 10), 'Burst events must exhibit high QPS (> 10)');
console.log(`[PASS] Query burst scenario models automated rapid lookups (${burstEvents.length} burst events from client-03)`);

// Test 5: High entropy scenario exhibits elevated Shannon entropy
const entStream = generateScenarioStream({ scenarioId: 'high_entropy', seed: 42 });
const covertEnt = entStream.events.filter(e => e.groundTruth === 'simulated_covert');
assert(covertEnt.length > 0, 'High entropy scenario must contain covert events');
assert(covertEnt.some(e => e.features.entropy >= 3.5), 'Covert events must show elevated Shannon entropy >= 3.5');
console.log(`[PASS] High entropy scenario generates covert exfiltration with elevated entropy (${covertEnt.length} covert events)`);

// Test 6: Long query scenario exhibits long subdomains and high payload ratio
const longStream = generateScenarioStream({ scenarioId: 'long_queries', seed: 42 });
const longCovert = longStream.events.filter(e => e.groundTruth === 'simulated_covert');
assert(longCovert.some(e => e.features.subdomainLength > 30), 'Long query covert events must have subdomain length > 30');
assert(longCovert.some(e => e.features.payloadToDomainRatio > 1.5), 'Long query covert events must have high payload ratio');
console.log(`[PASS] Long queries scenario pushes label boundaries (> 30 chars, high payload-to-domain ratio)`);

// Test 7: Packet loss scenario correctly drops packets and isolates detection
const lossStream = generateScenarioStream({ scenarioId: 'packet_loss_reconstruction', seed: 42, packetLoss: 25 });
const lostPackets = lossStream.events.filter(e => e.deliveryStatus === 'LOST');
assert(lostPackets.length > 0, 'Packet loss scenario must contain dropped datagrams');
// Verify detector evaluates packet content independently of transport status
lostPackets.forEach(pkt => {
  assert(pkt.analysis !== undefined && typeof pkt.analysis.score === 'number', 'Detector must evaluate lost packet content independently');
});
console.log(`[PASS] Packet loss scenario models ${lostPackets.length} dropped UDP datagrams without corrupting anomaly detection`);

// Test 8: HTTP Integration tests for scenario endpoints on port 3110
const TEST_PORT = 3110;
const server = app.listen(TEST_PORT, async () => {
  console.log(`Scenario test server running on port ${TEST_PORT}`);

  try {
    // 8a: GET /api/scenarios/list
    const listRes = await httpGet(`http://localhost:${TEST_PORT}/api/scenarios/list`);
    assert.strictEqual(listRes.status, 200);
    assert(Array.isArray(listRes.data) && listRes.data.length === 6);
    console.log('[PASS] API GET /api/scenarios/list returned 6 scenarios');

    // 8b: POST /api/scenarios/generate
    const genRes = await httpPost(`http://localhost:${TEST_PORT}/api/scenarios/generate`, {
      scenarioId: 'mixed_traffic',
      seed: 999
    });
    assert.strictEqual(genRes.status, 200);
    assert(genRes.data.events && genRes.data.events.length > 0);
    assert(genRes.data.topology && genRes.data.topology.clients.length === 3);
    console.log(`[PASS] API POST /api/scenarios/generate created ${genRes.data.events.length} replay events`);

    // 8c: POST /api/scenarios/evaluate
    const evalRes = await httpPost(`http://localhost:${TEST_PORT}/api/scenarios/evaluate`, {
      events: genRes.data.events
    });
    assert.strictEqual(evalRes.status, 200);
    assert(evalRes.data.ruleBased && evalRes.data.ruleBased.metrics.total === genRes.data.events.length);
    assert(evalRes.data.entropyBaseline && evalRes.data.entropyBaseline.metrics.total === genRes.data.events.length);
    console.log('[PASS] API POST /api/scenarios/evaluate calculated dual-detector confusion metrics on scenario stream');

    console.log('\n>>> ALL 8 SCENARIOS & REPLAY TEST MODULES PASSED CLEANLY! <<<');
  } catch (err) {
    console.error('Scenario test failure:', err);
    process.exit(1);
  } finally {
    server.close(() => {
      console.log('Scenario test server closed.');
    });
  }
});

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    }).on('error', reject);
  });
}

function httpPost(url, payload) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(payload);
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    const req = http.request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}
