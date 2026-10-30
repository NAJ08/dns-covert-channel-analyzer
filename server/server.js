/**
 * DNS Steganography & Covert Channel Analyzer
 * Express.js Server
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const { processEncodingPipeline, encodeMessage } = require('./encoder');
const { reconstructMessage, decodePayload } = require('./decoder');
const { simulateCovertDnsStream, createSimulatedPacket } = require('./simulator');
const { analyzeTrafficBatch, analyzeSingleQuery } = require('./detector');
const { generateLabeledDataset, splitDatasetByScenario } = require('./dataset');
const { runExperiment, calculateEvaluationMetrics } = require('./evaluator');
const { getScenarioList, generateScenarioStream } = require('./scenarios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Load baseline normal traffic
let normalTrafficData = null;
try {
  const samplePath = path.join(__dirname, '..', 'data', 'sample-traffic.json');
  normalTrafficData = JSON.parse(fs.readFileSync(samplePath, 'utf8'));
} catch (err) {
  console.warn('Notice: Could not load sample-traffic.json, using fallback normal baseline:', err.message);
  normalTrafficData = { queries: [], summary: {} };
}

// REST APIs

/**
 * Health check
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    system: 'DNS Steganography & Covert Channel Analyzer',
    mode: 'Local Simulation Only',
    version: '1.0.0'
  });
});

/**
 * Encode message into chunks & simulated DNS queries
 */
app.post('/api/encode', (req, res) => {
  try {
    const { message, method = 'base64', chunkSize = 16, domain = 'example.com', includeSeq = true } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Message string is required' });
    }
    const result = processEncodingPipeline(message, method, chunkSize, domain, includeSeq);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Decode simulated queries back into message
 */
app.post('/api/decode', (req, res) => {
  try {
    const { queries, method = 'base64', baseDomain = 'example.com', expectedTotal = null } = req.body;
    if (!queries || !Array.isArray(queries) || queries.length === 0) {
      return res.status(400).json({ error: 'Queries array is required' });
    }
    const result = reconstructMessage(queries, method, baseDomain, expectedTotal);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Run full covert channel simulation stream
 */
app.post('/api/simulate', (req, res) => {
  try {
    const {
      message = 'COMPUTER NETWORKS PROJECT',
      encoding = 'base64',
      domain = 'example.com',
      chunkSize = 16,
      queryType = 'A',
      interArrivalMs = 120,
      includeSeq = true,
      packetLoss = 0
    } = req.body;

    const stream = simulateCovertDnsStream({
      message,
      encoding,
      domain,
      chunkSize,
      queryType,
      interArrivalMs,
      includeSeq,
      packetLoss
    });

    // Also run detector on the delivered simulated packets (or all packets)
    const analysis = analyzeTrafficBatch(stream.packets);

    res.json({
      ...stream,
      analysis
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Analyze a batch of DNS queries or packets
 */
app.post('/api/analyze', (req, res) => {
  try {
    const { packets, queries } = req.body;
    const target = packets || queries;
    if (!target || !Array.isArray(target)) {
      return res.status(400).json({ error: 'Packets or queries array required for analysis' });
    }
    const report = analyzeTrafficBatch(target);
    res.json(report);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Get baseline normal DNS traffic
 */
app.get('/api/normal-traffic', (req, res) => {
  res.json(normalTrafficData);
});

/**
 * Compare normal baseline vs simulated covert traffic
 */
app.post('/api/compare', (req, res) => {
  try {
    const { covertPackets } = req.body;
    
    // Normal baseline analysis
    const normalAnalysis = analyzeTrafficBatch(normalTrafficData.queries);

    // Covert analysis
    let covertAnalysis = null;
    if (covertPackets && Array.isArray(covertPackets) && covertPackets.length > 0) {
      covertAnalysis = analyzeTrafficBatch(covertPackets);
    } else {
      // Generate default demo covert stream for comparison
      const demoStream = simulateCovertDnsStream({
        message: 'COMPUTER NETWORKS PROJECT',
        encoding: 'base64',
        domain: 'example.local',
        chunkSize: 16,
        queryType: 'A'
      });
      covertAnalysis = analyzeTrafficBatch(demoStream.packets);
    }

    // Comparison summary metrics
    const comparison = {
      metrics: [
        {
          name: 'Average Query Length',
          unit: 'chars',
          normal: normalAnalysis.indicators.averageQueryLength,
          covert: covertAnalysis.indicators.averageQueryLength,
          diff: Number((covertAnalysis.indicators.averageQueryLength - normalAnalysis.indicators.averageQueryLength).toFixed(1)),
          description: 'Covert queries embed payload data, substantially expanding character count.'
        },
        {
          name: 'Subdomain Length',
          unit: 'chars',
          normal: normalAnalysis.indicators.averageSubdomainLength,
          covert: covertAnalysis.indicators.averageSubdomainLength,
          diff: Number((covertAnalysis.indicators.averageSubdomainLength - normalAnalysis.indicators.averageSubdomainLength).toFixed(1)),
          description: 'Benign subdomains (e.g. www, mail) are concise; covert subdomains contain encoded chunks.'
        },
        {
          name: 'Character Shannon Entropy',
          unit: 'bits/char',
          normal: normalAnalysis.indicators.averageEntropy,
          covert: covertAnalysis.indicators.averageEntropy,
          diff: Number((covertAnalysis.indicators.averageEntropy - normalAnalysis.indicators.averageEntropy).toFixed(2)),
          description: 'Encoded/encrypted payloads exhibit significantly higher randomness than natural language.'
        },
        {
          name: 'Unusual Character Ratio',
          unit: '%',
          normal: Number((normalAnalysis.indicators.averageUnusualCharRatio * 100).toFixed(1)),
          covert: Number((covertAnalysis.indicators.averageUnusualCharRatio * 100).toFixed(1)),
          diff: Number(((covertAnalysis.indicators.averageUnusualCharRatio - normalAnalysis.indicators.averageUnusualCharRatio) * 100).toFixed(1)),
          description: 'High frequency of digits, symbols (=), and mixed case uncharacteristic of normal hostnames.'
        },
        {
          name: 'Payload-to-Domain Ratio',
          unit: 'x',
          normal: normalAnalysis.indicators.averagePayloadDomainRatio,
          covert: covertAnalysis.indicators.averagePayloadDomainRatio,
          diff: Number((covertAnalysis.indicators.averagePayloadDomainRatio - normalAnalysis.indicators.averagePayloadDomainRatio).toFixed(2)),
          description: 'In covert traffic, the payload label often dwarfs the parent authoritative domain.'
        },
        {
          name: 'Suspicion Score',
          unit: '/100',
          normal: normalAnalysis.suspicionScore,
          covert: covertAnalysis.suspicionScore,
          diff: covertAnalysis.suspicionScore - normalAnalysis.suspicionScore,
          description: 'Rule-based anomaly score calculated from composite feature deviations.'
        }
      ],
      normal: normalAnalysis,
      covert: covertAnalysis
    };

    res.json(comparison);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Cache for latest evaluation experiment
let lastExperimentReport = null;

/**
 * Generate a synthetic labeled evaluation dataset
 */
app.post('/api/evaluation/dataset', (req, res) => {
  try {
    const { sampleCount = 100, seed = 42, normalRatio = 0.5, encoding = 'all', packetLoss = 0 } = req.body;

    if (sampleCount !== undefined && (isNaN(sampleCount) || sampleCount < 10 || sampleCount > 2000)) {
      return res.status(400).json({ error: 'sampleCount must be a number between 10 and 2000' });
    }
    if (normalRatio !== undefined && (isNaN(normalRatio) || normalRatio < 0.1 || normalRatio > 0.9)) {
      return res.status(400).json({ error: 'normalRatio must be a float between 0.1 and 0.9' });
    }

    const dataset = generateLabeledDataset({
      sampleCount: parseInt(sampleCount, 10),
      seed,
      normalRatio: parseFloat(normalRatio),
      encoding,
      packetLoss: parseInt(packetLoss, 10)
    });

    res.json(dataset);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Run a scientific detection performance evaluation experiment
 */
app.post('/api/evaluation/run', (req, res) => {
  try {
    const {
      sampleCount = 100,
      seed = 42,
      splitRatio = 0.3,
      entropyThreshold = null,
      autoCalibrate = true,
      encoding = 'all',
      packetLoss = 0
    } = req.body;

    if (sampleCount !== undefined && (isNaN(sampleCount) || sampleCount < 10 || sampleCount > 2000)) {
      return res.status(400).json({ error: 'sampleCount must be a number between 10 and 2000' });
    }
    if (splitRatio !== undefined && (isNaN(splitRatio) || splitRatio < 0.1 || splitRatio > 0.7)) {
      return res.status(400).json({ error: 'splitRatio must be a float between 0.1 and 0.7' });
    }
    if (entropyThreshold !== null && entropyThreshold !== undefined && (isNaN(entropyThreshold) || entropyThreshold < 0.5 || entropyThreshold > 6.0)) {
      return res.status(400).json({ error: 'entropyThreshold must be a float between 0.5 and 6.0' });
    }

    const report = runExperiment({
      sampleCount: parseInt(sampleCount, 10),
      seed,
      splitRatio: parseFloat(splitRatio),
      entropyThreshold: entropyThreshold !== null && entropyThreshold !== undefined ? parseFloat(entropyThreshold) : null,
      autoCalibrate: autoCalibrate !== false,
      encoding,
      packetLoss: parseInt(packetLoss, 10)
    });

    lastExperimentReport = report;
    res.json(report);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Get the latest cached evaluation experiment
 */
app.get('/api/evaluation/latest', (req, res) => {
  if (!lastExperimentReport) {
    lastExperimentReport = runExperiment({ sampleCount: 100, seed: 42, autoCalibrate: true });
  }
  res.json(lastExperimentReport);
});

/**
 * Get available predefined traffic scenarios
 */
app.get('/api/scenarios/list', (req, res) => {
  res.json(getScenarioList());
});

/**
 * Generate a synthetic DNS scenario stream for traffic replay & investigation
 */
app.post('/api/scenarios/generate', (req, res) => {
  try {
    const { scenarioId = 'normal_browsing', seed = 42, packetLoss = 0 } = req.body;
    const stream = generateScenarioStream({
      scenarioId,
      seed: parseInt(seed, 10) || 42,
      packetLoss: parseInt(packetLoss, 10) || 0
    });
    res.json(stream);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Evaluate scenario stream performance against ground-truth labels
 */
app.post('/api/scenarios/evaluate', (req, res) => {
  try {
    const { events } = req.body;
    if (!events || !Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'Events array is required for evaluation' });
    }

    const rulePredictions = events.map(e => ({
      groundTruth: e.groundTruth,
      predicted: (e.analysis?.score >= 50 ? 'simulated_covert' : 'normal')
    }));
    const entropyThreshold = 3.6;
    const entropyPredictions = events.map(e => ({
      groundTruth: e.groundTruth,
      predicted: ((e.features?.entropy || 0) > entropyThreshold ? 'simulated_covert' : 'normal')
    }));

    const ruleMetrics = calculateEvaluationMetrics(rulePredictions);
    const entropyMetrics = calculateEvaluationMetrics(entropyPredictions);

    // Identify diagnostic error cases
    const falsePositives = [];
    const falseNegatives = [];

    events.forEach(e => {
      const isCov = e.groundTruth === 'simulated_covert';
      const rulePred = e.analysis?.score >= 50 ? 'simulated_covert' : 'normal';
      if (!isCov && rulePred === 'simulated_covert') {
        falsePositives.push({
          id: e.id,
          queryName: e.queryName,
          client: e.client?.name,
          score: e.analysis?.score,
          entropy: e.features?.entropy,
          reasons: e.analysis?.reasons
        });
      } else if (isCov && rulePred === 'normal') {
        falseNegatives.push({
          id: e.id,
          queryName: e.queryName,
          client: e.client?.name,
          score: e.analysis?.score,
          entropy: e.features?.entropy,
          reasons: e.analysis?.reasons
        });
      }
    });

    res.json({
      totalEvaluated: events.length,
      ruleBased: {
        name: 'Multi-Feature Rule-Based Detector',
        metrics: ruleMetrics,
        falsePositives,
        falseNegatives
      },
      entropyBaseline: {
        name: `Entropy-Threshold Baseline (T > ${entropyThreshold})`,
        threshold: entropyThreshold,
        metrics: entropyMetrics
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Start Server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` DNS Steganography & Covert Channel Analyzer`);
    console.log(` Educational Simulation Tool for Computer Networks`);
    console.log(` Server running at http://localhost:${PORT}`);
    console.log(` Mode: STRICTLY LOCAL IN-MEMORY SIMULATION`);
    console.log(`=======================================================`);
  });
}

module.exports = app;
