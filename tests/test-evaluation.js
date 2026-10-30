/**
 * Comprehensive Automated Tests for Scientific Evaluation Engine
 * Phase 7 Verification Suite
 */

const assert = require('assert');
const http = require('http');
const { calculateShannonEntropy } = require('../server/detector');
const { generateLabeledDataset, splitDatasetByScenario, extractQueryFeatures } = require('../server/dataset');
const { calculateEvaluationMetrics, calibrateEntropyThreshold, runExperiment } = require('../server/evaluator');
const app = require('../server/server');

console.log('--- Starting Scientific Evaluation Engine Tests ---');

// 1. Shannon Entropy on known strings
assert.strictEqual(calculateShannonEntropy(''), 0, 'Empty string should have 0 entropy');
assert.strictEqual(calculateShannonEntropy('aaaaa'), 0, 'Constant string should have 0 entropy');
// "ab" equal frequency: - (0.5*log2(0.5) + 0.5*log2(0.5)) = - (-0.5 - 0.5) = 1.000
assert.strictEqual(calculateShannonEntropy('abababab'), 1.0, 'Binary equal distribution should have exactly 1.0 entropy');
// 4 characters equal frequency: - 4 * (0.25 * log2(0.25)) = - 4 * (0.25 * -2) = 2.000
assert.strictEqual(calculateShannonEntropy('abcd'), 2.0, '4 equal characters should have exactly 2.0 entropy');
console.log('[PASS] Shannon Entropy calculations on known theoretical strings');

// 2. Hand-calculated Confusion Matrix & Metrics
// Scenario:
// 10 samples total:
// Sample 1: actual covert, pred covert (TP)
// Sample 2: actual covert, pred covert (TP)
// Sample 3: actual covert, pred covert (TP)
// Sample 4: actual covert, pred normal (FN)
// Sample 5: actual normal, pred normal (TN)
// Sample 6: actual normal, pred normal (TN)
// Sample 7: actual normal, pred normal (TN)
// Sample 8: actual normal, pred normal (TN)
// Sample 9: actual normal, pred covert (FP)
// Sample 10: actual normal, pred covert (FP)
// Totals:
// TP = 3, FN = 1 (actual covert = 4)
// TN = 4, FP = 2 (actual normal = 6)
// Total = 10
// Hand calculations:
// Accuracy = (3 + 4) / 10 = 7 / 10 = 0.7000
// Precision = 3 / (3 + 2) = 3 / 5 = 0.6000
// Recall = 3 / (3 + 1) = 3 / 4 = 0.7500
// Specificity = 4 / (4 + 2) = 4 / 6 = 0.6667
// F1 = 2 * (0.6 * 0.75) / (0.6 + 0.75) = 2 * 0.45 / 1.35 = 0.90 / 1.35 = 0.6667
// FPR = 2 / (2 + 4) = 2 / 6 = 0.3333

const handCraftedPredictions = [
  { groundTruth: 'simulated_covert', predicted: 'simulated_covert' },
  { groundTruth: 'simulated_covert', predicted: 'simulated_covert' },
  { groundTruth: 'simulated_covert', predicted: 'simulated_covert' },
  { groundTruth: 'simulated_covert', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'simulated_covert' },
  { groundTruth: 'normal', predicted: 'simulated_covert' }
];

const handMetrics = calculateEvaluationMetrics(handCraftedPredictions);
assert.strictEqual(handMetrics.total, 10);
assert.strictEqual(handMetrics.tp, 3);
assert.strictEqual(handMetrics.fn, 1);
assert.strictEqual(handMetrics.tn, 4);
assert.strictEqual(handMetrics.fp, 2);
assert.strictEqual(handMetrics.matrixValid, true);
assert.strictEqual(handMetrics.accuracy, 0.7);
assert.strictEqual(handMetrics.precision, 0.6);
assert.strictEqual(handMetrics.recall, 0.75);
assert.strictEqual(handMetrics.specificity, 0.6667);
assert.strictEqual(handMetrics.f1Score, 0.6667);
assert.strictEqual(handMetrics.falsePositiveRate, 0.3333);
console.log('[PASS] Hand-calculated confusion matrix and metrics match theoretical formulas');

// 3. Zero-Denominator Handling (Must return null, never 0 or NaN)
// Case A: All predicted normal (TP = 0, FP = 0 -> Precision denominator TP + FP = 0)
const noPositivePredictions = [
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'simulated_covert', predicted: 'normal' }
];
const zeroPrecisionMetrics = calculateEvaluationMetrics(noPositivePredictions);
assert.strictEqual(zeroPrecisionMetrics.precision, null, 'Precision must be null when TP+FP=0');
assert.strictEqual(zeroPrecisionMetrics.f1Score, null, 'F1 score must be null when precision is null');

// Case B: All actual normal (TP = 0, FN = 0 -> Recall denominator TP + FN = 0)
const noActualCovert = [
  { groundTruth: 'normal', predicted: 'normal' },
  { groundTruth: 'normal', predicted: 'simulated_covert' }
];
const zeroRecallMetrics = calculateEvaluationMetrics(noActualCovert);
assert.strictEqual(zeroRecallMetrics.recall, null, 'Recall must be null when TP+FN=0');
assert.strictEqual(zeroRecallMetrics.f1Score, null, 'F1 score must be null when recall is null');

// Case C: Empty prediction set
const emptyMetrics = calculateEvaluationMetrics([]);
assert.strictEqual(emptyMetrics.total, 0);
assert.strictEqual(emptyMetrics.accuracy, null);
assert.strictEqual(emptyMetrics.precision, null);
assert.strictEqual(emptyMetrics.recall, null);
assert.strictEqual(emptyMetrics.specificity, null);
assert.strictEqual(emptyMetrics.f1Score, null);
assert.strictEqual(emptyMetrics.falsePositiveRate, null);
console.log('[PASS] Zero-denominator safety verified: returns null without misleading zeros');

// 4. Deterministic Dataset Generation with Seed
const setSeedA1 = generateLabeledDataset({ seed: 42, sampleCount: 50 });
const setSeedA2 = generateLabeledDataset({ seed: 42, sampleCount: 50 });
assert.strictEqual(setSeedA1.samples.length, 50);
assert.strictEqual(setSeedA1.samples.length, setSeedA2.samples.length);

for (let i = 0; i < 50; i++) {
  assert.strictEqual(setSeedA1.samples[i].queryName, setSeedA2.samples[i].queryName, `Sample ${i} mismatch for same seed`);
  assert.strictEqual(setSeedA1.samples[i].entropy, setSeedA2.samples[i].entropy);
  assert.strictEqual(setSeedA1.samples[i].label, setSeedA2.samples[i].label);
}
console.log('[PASS] Deterministic dataset generation: identical seeds produce bitwise-identical samples');

// 5. Different Seeds produce Distinct Datasets
const setSeedB = generateLabeledDataset({ seed: 9999, sampleCount: 50 });
let differences = 0;
for (let i = 0; i < 50; i++) {
  if (setSeedA1.samples[i].queryName !== setSeedB.samples[i].queryName) {
    differences++;
  }
}
assert.ok(differences > 30, 'Different seeds should produce significantly different sample query names');
console.log(`[PASS] Seed variation verified: ${differences}/50 queries differ with distinct seeds`);

// 6. Scenario-Based Splitting (Leakage Prevention)
const splitTest = splitDatasetByScenario(setSeedA1.samples, 0.3, 42);
assert.ok(splitTest.calibrationSet.length > 0, 'Calibration set should have samples');
assert.ok(splitTest.evaluationSet.length > 0, 'Evaluation set should have samples');
assert.strictEqual(splitTest.calibrationSet.length + splitTest.evaluationSet.length, 50, 'Total samples must be conserved');

const calibrationScenarios = new Set(splitTest.calibrationSet.map(s => s.scenarioId));
const evaluationScenarios = new Set(splitTest.evaluationSet.map(s => s.scenarioId));

let leakageCount = 0;
for (const scn of calibrationScenarios) {
  if (evaluationScenarios.has(scn)) {
    leakageCount++;
  }
}
assert.strictEqual(leakageCount, 0, 'ZERO scenario leakage permitted between calibration and evaluation sets');
console.log('[PASS] Zero scenario leakage verified: calibration and evaluation sets are strictly disjoint by scenario');

// 7. Full Experiment Execution & Dual Detector Evaluation
const exp = runExperiment({
  sampleCount: 80,
  seed: 12345,
  splitRatio: 0.25,
  autoCalibrate: true,
  packetLoss: 10
});

assert.ok(exp.experimentId.startsWith('EXP-'));
assert.strictEqual(exp.datasetSummary.scenarioLeakageDetected, false);
assert.ok(exp.datasetSummary.evaluationCount > 0);

// Both detectors evaluated on EXACT SAME evaluation sample count
assert.strictEqual(exp.detectors.ruleBased.metrics.total, exp.datasetSummary.evaluationCount);
assert.strictEqual(exp.detectors.entropyBaseline.metrics.total, exp.datasetSummary.evaluationCount);
assert.strictEqual(exp.detailedEvaluations.length, exp.datasetSummary.evaluationCount);

// Verify matrix integrity
const mRule = exp.detectors.ruleBased.metrics;
assert.strictEqual(mRule.tp + mRule.tn + mRule.fp + mRule.fn, exp.datasetSummary.evaluationCount);
assert.strictEqual(mRule.matrixValid, true);

const mEnt = exp.detectors.entropyBaseline.metrics;
assert.strictEqual(mEnt.tp + mEnt.tn + mEnt.fp + mEnt.fn, exp.datasetSummary.evaluationCount);
assert.strictEqual(mEnt.matrixValid, true);

// Feature distributions present
assert.ok(exp.featureDistributions.entropy.normal.mean > 0);
assert.ok(exp.featureDistributions.entropy.covert.mean > 0);

// Error analysis structures present
assert.ok(Array.isArray(exp.errorAnalysis.ruleBased.falsePositives));
assert.ok(Array.isArray(exp.errorAnalysis.ruleBased.falseNegatives));

// Packet loss reported separately
assert.ok(exp.reconstructionSummary !== null);
assert.strictEqual(exp.reconstructionSummary.packetLossSetting, '10%');
console.log('[PASS] Full experiment pipeline: dual detectors evaluated on identical held-out samples with verified matrix sums');

// 8. Server Integration for New Evaluation Endpoints
const TEST_PORT = 3105;
const server = app.listen(TEST_PORT, async () => {
  console.log(`Evaluation test server running on port ${TEST_PORT}`);

  function postJson(url, data) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      const payload = JSON.stringify(data);
      const req = http.request({
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: body });
          }
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  function getJson(url) {
    return new Promise((resolve, reject) => {
      http.get(url, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: body });
          }
        });
      }).on('error', reject);
    });
  }

  try {
    // Test POST /api/evaluation/dataset
    const dsRes = await postJson(`http://localhost:${TEST_PORT}/api/evaluation/dataset`, {
      sampleCount: 40,
      seed: 42
    });
    assert.strictEqual(dsRes.status, 200);
    assert.strictEqual(dsRes.data.samples.length, 40);
    console.log('[PASS] API POST /api/evaluation/dataset returned valid labeled dataset');

    // Test POST /api/evaluation/run
    const runRes = await postJson(`http://localhost:${TEST_PORT}/api/evaluation/run`, {
      sampleCount: 50,
      seed: 42,
      splitRatio: 0.3,
      autoCalibrate: true
    });
    assert.strictEqual(runRes.status, 200);
    assert.ok(runRes.data.detectors.ruleBased.metrics.accuracy !== undefined);
    assert.ok(runRes.data.detectors.entropyBaseline.metrics.accuracy !== undefined);
    console.log('[PASS] API POST /api/evaluation/run executed experiment successfully');

    // Test Validation on invalid sampleCount (out of range)
    const errRes = await postJson(`http://localhost:${TEST_PORT}/api/evaluation/run`, {
      sampleCount: 5 // min is 10
    });
    assert.strictEqual(errRes.status, 400);
    assert.ok(errRes.data.error.includes('sampleCount'));
    console.log('[PASS] API POST /api/evaluation/run input validation rejected invalid sample count with HTTP 400');

    // Test GET /api/evaluation/latest
    const latestRes = await getJson(`http://localhost:${TEST_PORT}/api/evaluation/latest`);
    assert.strictEqual(latestRes.status, 200);
    assert.ok(latestRes.data.detectors !== undefined);
    console.log('[PASS] API GET /api/evaluation/latest returned cached report');

    console.log('\n>>> ALL 8 EVALUATION TEST MODULES PASSED CLEANLY! <<<');
  } catch (err) {
    console.error('[FAIL] Evaluation test failure:', err);
    process.exitCode = 1;
  } finally {
    server.close(() => {
      console.log('Evaluation test server closed.');
    });
  }
});
