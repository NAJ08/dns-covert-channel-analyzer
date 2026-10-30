/**
 * Automated Verification Script
 * Tests encoding, decoding, simulator, anomaly detector, DNS Request/Response, and packet loss.
 */

const assert = require('assert');
const { encodeMessage, processEncodingPipeline } = require('../server/encoder');
const { decodePayload, reconstructMessage } = require('../server/decoder');
const { createSimulatedPacket, simulateCovertDnsStream } = require('../server/simulator');
const { calculateShannonEntropy, analyzeSingleQuery, analyzeTrafficBatch } = require('../server/detector');

console.log('--- Starting Automated Tests ---');

// 1. Test All Encoders & Decoders
const testMessage = 'COMPUTER NETWORKS PROJECT';
const methods = ['base64', 'hex', 'binary', 'base32'];

for (const method of methods) {
  const encoded = encodeMessage(testMessage, method);
  const decoded = decodePayload(encoded, method);
  assert.strictEqual(decoded, testMessage, `Failed round-trip for ${method}`);
  console.log(`[PASS] Round-trip encoding/decoding (${method}): "${testMessage}" -> "${encoded.slice(0, 20)}..." -> "${decoded}"`);
}

// 2. Test Pipeline Chunking & Reassembly (google.com default & pktXX- prefix)
const pipeline = processEncodingPipeline(testMessage, 'base64', 8, 'google.com', true);
assert.ok(pipeline.chunks.length > 1, 'Chunking should produce multiple chunks');
assert.ok(pipeline.chunks[0].queryName.includes('.google.com'), 'Should use simulated google.com domain');
assert.ok(/^pkt\d+-/i.test(pipeline.chunks[0].subdomain), 'Should use pktXX- sequence format');
console.log(`[PASS] Pipeline generated ${pipeline.chunks.length} chunks on google.com (Sample query: "${pipeline.chunks[0].queryName}")`);

const reconstructed = reconstructMessage(pipeline.chunks, 'base64', 'google.com');
assert.strictEqual(reconstructed.success, true, 'Reconstruction should succeed');
assert.strictEqual(reconstructed.reconstructionStatus, 'SUCCESS', 'Reconstruction status should be SUCCESS');
assert.strictEqual(reconstructed.decodedMessage, testMessage, 'Decoded message must match original');
console.log(`[PASS] Successfully reconstructed original message from chunked queries!`);

// 3. Test Shannon Entropy
const naturalEntropy = calculateShannonEntropy('google');
const randomEntropy = calculateShannonEntropy('aGVsbG8xMjM0NTY3OA==');
assert.ok(randomEntropy > naturalEntropy, 'Random/Base64 string should have higher entropy than simple English');
console.log(`[PASS] Shannon Entropy: "google" = ${naturalEntropy}, "aGVsbG8xMjM0NTY3OA==" = ${randomEntropy}`);

// 4. Test Simulated Packet Generation (RFC 1035 model)
const singlePacket = createSimulatedPacket({
  packetNumber: 1,
  totalPackets: 1,
  queryName: 'pkt01-aGVsbG8=.google.com',
  encodedPayload: 'aGVsbG8=',
  queryType: 'A',
  baseDomain: 'google.com'
});
assert.strictEqual(singlePacket.isSimulated, true);
assert.strictEqual(singlePacket.dns.header.qdcount, 1);
assert.strictEqual(singlePacket.transport.dstPort, 53);
assert.ok(singlePacket.dns.payload.hexDump.length > 10);
console.log(`[PASS] RFC 1035 Simulated Packet generated: TxID=${singlePacket.dns.header.transactionId}, WireBytes=${singlePacket.dns.payload.rawPacketBytes}`);

// 5. Test Anomaly Detector & Scoring
const demoStream = simulateCovertDnsStream({
  message: 'SECRET ATTACK PLAN DATA EXFILTRATION SIMULATION',
  encoding: 'base64',
  chunkSize: 16,
  domain: 'google.com'
});
const covertReport = analyzeTrafficBatch(demoStream.packets);
console.log(`[PASS] Covert Stream Score: ${covertReport.suspicionScore}/100 (${covertReport.classification})`);
assert.ok(covertReport.suspicionScore >= 60, 'Covert traffic should have high suspicion score');
assert.ok(covertReport.ruleContributions.length > 0, 'Should provide explainable rule contributions');

// Test Normal Traffic scoring
const normalQueries = [
  'www.google.com',
  'en.wikipedia.org',
  'api.github.com',
  'fonts.googleapis.com'
];
const normalReport = analyzeTrafficBatch(normalQueries);
console.log(`[PASS] Normal Traffic Score: ${normalReport.suspicionScore}/100 (${normalReport.classification})`);
assert.ok(normalReport.suspicionScore <= 30, 'Normal traffic score should be <= 30 (Normal)');

// 6. Test DNS Response Packet Model
assert.ok(singlePacket.request, 'Packet must contain request object');
assert.ok(singlePacket.response, 'Packet must contain response object');
assert.strictEqual(singlePacket.request.transactionId, singlePacket.response.transactionId, 'Request and Response TxID must match');
assert.strictEqual(singlePacket.response.ancount, 1, 'Response must contain 1 simulated answer');
assert.ok(singlePacket.response.simulatedAnswer.rdata.length > 0, 'Response must provide simulated answer RDATA');
console.log(`[PASS] Paired DNS Response generated: TxID=${singlePacket.response.transactionId}, Answer=${singlePacket.response.simulatedAnswer.rdata}`);

// 7. Test Network Protocol Stack & Resolution Trace
assert.ok(singlePacket.protocolStack.application, 'Must model Application layer (DNS)');
assert.ok(singlePacket.protocolStack.transport, 'Must model Transport layer (UDP)');
assert.ok(singlePacket.protocolStack.internet, 'Must model Internet layer (IP)');
assert.ok(singlePacket.protocolStack.networkAccess, 'Must model Network Access layer (Ethernet)');
assert.ok(singlePacket.resolutionTrace.length >= 6, 'Must generate full DNS resolution flow trace');
console.log(`[PASS] Network Protocol Stack & Resolution Trace modeled (Layers: Application, Transport, Internet, Network Access)`);

// 8. Test Packet Loss Simulation (0% vs >0%)
const zeroLossStream = simulateCovertDnsStream({
  message: 'COMPUTER NETWORKS PROJECT',
  encoding: 'base64',
  chunkSize: 16,
  packetLoss: 0
});
assert.strictEqual(zeroLossStream.packetsLost, 0, 'Zero loss should have 0 lost packets');
assert.strictEqual(zeroLossStream.reconstruction.reconstructionStatus, 'SUCCESS', 'Zero loss should succeed reconstruction');
assert.strictEqual(zeroLossStream.reconstruction.decodedMessage, 'COMPUTER NETWORKS PROJECT');
console.log(`[PASS] Packet Loss 0%: All ${zeroLossStream.packetsDelivered} packets delivered, Reconstruction: SUCCESS`);

const simulatedLossStream = simulateCovertDnsStream({
  message: 'COMPUTER NETWORKS PROJECT',
  encoding: 'base64',
  chunkSize: 8, // generates ~5-6 packets
  packetLoss: 25
});
assert.ok(simulatedLossStream.packetsLost >= 1, 'Packet loss > 0% should drop at least 1 packet');
assert.strictEqual(simulatedLossStream.reconstruction.reconstructionStatus, 'FAILED', 'Missing packets should cause FAILED reconstruction');
assert.ok(simulatedLossStream.reconstruction.missingPackets.length >= 1, 'Should report missing packet numbers');
console.log(`[PASS] Packet Loss Simulation: ${simulatedLossStream.packetsLost} packets lost, Missing: [${simulatedLossStream.reconstruction.missingPackets.join(', ')}], Status: FAILED`);

console.log('\n>>> ALL 8 EXTENDED TEST SUITES PASSED CLEANLY! <<<');
