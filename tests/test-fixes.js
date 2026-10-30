/**
 * Regression tests for the review fixes:
 *  1. Stratified calibration/evaluation split (both classes on both sides, no leakage)
 *  2. DNS-valid query labels for every encoding + exact reconstruction
 *  3. Detector counts uppercase payload characters
 *  4. Covert-channel defaults use reserved example domains
 */
const assert = require('assert');
const { generateLabeledDataset, splitDatasetByScenario } = require('../server/dataset');
const { processEncodingPipeline } = require('../server/encoder');
const { reconstructMessage } = require('../server/decoder');
const { analyzeSingleQuery } = require('../server/detector');

console.log('--- Starting Review-Fix Regression Tests ---');

// 1. Stratified split
for (let seed = 1; seed <= 50; seed++) {
  const data = generateLabeledDataset({ sampleCount: 100, seed });
  const samples = Array.isArray(data) ? data : (data.samples || Object.values(data).find(Array.isArray));
  const { calibrationSet, evaluationSet } = splitDatasetByScenario(samples, 0.3, seed);
  for (const set of [calibrationSet, evaluationSet]) {
    assert.ok(set.some(s => s.label === 'normal'), `seed ${seed}: split side missing normal samples`);
    assert.ok(set.some(s => s.label === 'simulated_covert'), `seed ${seed}: split side missing covert samples`);
  }
  const calScn = new Set(calibrationSet.map(s => s.scenarioId));
  assert.ok(!evaluationSet.some(s => calScn.has(s.scenarioId)), `seed ${seed}: scenario leakage`);
}
console.log('[PASS] Stratified split: both classes in calibration and evaluation for seeds 1-50, zero scenario leakage');

// 2. DNS-valid labels (letters, digits, hyphen, underscore; <= 63 octets) and exact round trip
const msg = 'Hello? World>>>~~ test/message+for=dns';
for (const method of ['base64', 'base32', 'hex', 'binary']) {
  const p = processEncodingPipeline(msg, method, 16, 'example.com');
  for (const c of p.chunks) {
    assert.ok(/^[A-Za-z0-9_-]+$/.test(c.subdomain), `${method}: invalid label characters in ${c.subdomain}`);
    assert.ok(c.subdomain.length <= 63, `${method}: label exceeds 63 octets`);
  }
  const r = reconstructMessage(p.chunks.map(c => c.queryName), method, 'example.com');
  assert.ok(Object.values(r).includes(msg), `${method}: reconstruction mismatch`);
}
console.log('[PASS] All encodings produce DNS-valid labels and reconstruct the exact message');

// 3. Uppercase characters counted by the detector
const upper = analyzeSingleQuery('pkt01-IRHFGX2UKVHE4RKML5.example.com');
const lower = analyzeSingleQuery('www.wikipedia.org');
assert.ok(upper.unusualCharRatio > 0.5, 'Uppercase Base32 payload should have a high unusual-character ratio');
assert.strictEqual(lower.unusualCharRatio, 0, 'Plain lowercase hostname should have zero unusual characters');
console.log(`[PASS] Detector counts uppercase payload characters (Base32 label ratio = ${upper.unusualCharRatio})`);

// 4. Default covert domain
const def = processEncodingPipeline('TEST');
assert.ok(def.chunks[0].queryName.endsWith('.example.com'), 'Default covert domain should be example.com');
console.log('[PASS] Covert-channel pipeline defaults to reserved example.com domain');

console.log('>>> ALL REVIEW-FIX REGRESSION TESTS PASSED <<<');
