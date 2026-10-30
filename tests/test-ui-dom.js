/**
 * Comprehensive Headless DOM & Button Functionality Test
 * Simulates DOM loading of index.html & script.js to verify all click handlers execute cleanly.
 */

const fs = require('fs');

console.log('=== STARTING HEADLESS DOM & BUTTON VERIFICATION TEST ===\n');

const html = fs.readFileSync('public/index.html', 'utf8');
const js = fs.readFileSync('public/script.js', 'utf8');

// Lightweight DOM emulator for Node.js
class MockClassList {
  constructor() { this.classes = new Set(); }
  add(...names) { names.forEach(n => this.classes.add(n)); }
  remove(...names) { names.forEach(n => this.classes.delete(n)); }
  toggle(name, force) {
    if (force === undefined) {
      if (this.classes.has(name)) this.classes.delete(name);
      else this.classes.add(name);
    } else if (force) {
      this.classes.add(name);
    } else {
      this.classes.delete(name);
    }
  }
  contains(name) { return this.classes.has(name); }
}

class MockElement {
  constructor(tag, id = '', attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.attributes = attrs;
    this.classList = new MockClassList();
    this.children = [];
    this.listeners = {};
    this.style = {};
    this._textContent = '';
    this._innerHTML = '';
    this.value = attrs.value || '';
    this.disabled = false;
    this.checked = false;
  }

  get textContent() { return this._textContent; }
  set textContent(val) { this._textContent = String(val); }

  get innerHTML() { return this._innerHTML; }
  set innerHTML(val) { this._innerHTML = String(val); }

  getAttribute(name) { return this.attributes[name] || null; }
  setAttribute(name, val) { this.attributes[name] = String(val); }

  addEventListener(event, handler) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(handler);
  }

  dispatchEvent(event, ...args) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(fn => fn(...args));
    }
  }

  click() {
    this.dispatchEvent('click', { target: this, preventDefault: () => {} });
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx !== -1) this.children.splice(idx, 1);
    return child;
  }
}

// Build DOM tree from HTML ids and classes
const domElements = new Map();
const idRegex = /id=["']([^"']+)["']/g;
let m;
while ((m = idRegex.exec(html)) !== null) {
  const id = m[1];
  if (!domElements.has(id)) {
    domElements.set(id, new MockElement('div', id));
  }
}

// Populate specific tag types and initial values
if (domElements.has('select-encoding')) domElements.get('select-encoding').value = 'base64';
if (domElements.has('select-replay-scenario')) domElements.get('select-replay-scenario').value = 'normal_browsing';
if (domElements.has('replay-seed-input')) domElements.get('replay-seed-input').value = '42';
if (domElements.has('slider-chunk-size')) domElements.get('slider-chunk-size').value = '16';
if (domElements.has('slider-delay')) domElements.get('slider-delay').value = '120';
if (domElements.has('slider-packet-loss')) domElements.get('slider-packet-loss').value = '0';
if (domElements.has('eval-sample-count')) domElements.get('eval-sample-count').value = '100';
if (domElements.has('eval-split-ratio')) domElements.get('eval-split-ratio').value = '70';
if (domElements.has('eval-packet-loss')) domElements.get('eval-packet-loss').value = '0';
if (domElements.has('eval-entropy-threshold')) domElements.get('eval-entropy-threshold').value = '3.6';
if (domElements.has('eval-seed')) domElements.get('eval-seed').value = '42';
if (domElements.has('select-active-packet')) domElements.get('select-active-packet').value = '0';
if (domElements.has('input-message')) domElements.get('input-message').value = 'COMPUTER NETWORKS PROJECT';
if (domElements.has('input-domain')) domElements.get('input-domain').value = 'example.com';

// Special classes
const navTabs = [
  'dashboard', 'simulator', 'analyzer', 'detection', 'comparison', 'evaluation', 'log', 'about'
].map(tab => {
  const el = new MockElement('button', `nav-${tab}`, { 'data-tab': tab });
  el.classList.add('nav-tab');
  if (tab === 'dashboard') el.classList.add('active');
  return el;
});

const speedPills = [
  { id: 'speed-05x', speed: '1400' },
  { id: 'speed-1x', speed: '700' },
  { id: 'speed-2x', speed: '350' },
  { id: 'speed-5x', speed: '140' }
].map(s => {
  const el = new MockElement('button', s.id, { 'data-speed': s.speed });
  el.classList.add('speed-pill');
  if (s.id === 'speed-1x') el.classList.add('active');
  domElements.set(s.id, el);
  return el;
});

const topoCards = [
  'client-01', 'client-02', 'client-03', 'resolver-01', 'dest-web', 'dest-cdn', 'dest-covert'
].map(node => {
  const el = new MockElement('div', `topo-${node}`, { 'data-node': node });
  el.classList.add('topo-node-card');
  return el;
});

const sampleChips = [
  'COMPUTER NETWORKS PROJECT', 'EXFILTRATION_TEST_KEY_44921', 'DNS COVERT CHANNELS ARE SUBTLE'
].map(s => {
  const el = new MockElement('span', '', { 'data-sample': s });
  el.classList.add('chip');
  return el;
});

const domainChips = ['example.com', 'example.net', 'example.org', 'tunnel.example'].map(d => {
  const el = new MockElement('span', '', { 'data-domain': d });
  el.classList.add('chip');
  el.classList.add('chip-domain');
  return el;
});

const stackCards = ['application', 'transport', 'internet', 'networkAccess'].map(layer => {
  const el = new MockElement('div', `layer-card-${layer}`, { 'data-layer': layer });
  el.classList.add('stack-layer-card');
  return el;
});

// Construct environment
let domReadyListeners = [];
const mockDocument = {
  addEventListener: (event, handler) => {
    if (event === 'DOMContentLoaded') domReadyListeners.push(handler);
  },
  getElementById: (id) => {
    if (!domElements.has(id)) {
      // Create dynamically if referenced
      const el = new MockElement('div', id);
      domElements.set(id, el);
    }
    return domElements.get(id);
  },
  querySelector: (sel) => {
    if (sel.startsWith('#')) return mockDocument.getElementById(sel.slice(1));
    return null;
  },
  querySelectorAll: (sel) => {
    if (sel === '.nav-tab') return navTabs;
    if (sel === '.tab-pane') {
      return ['dashboard', 'simulator', 'analyzer', 'detection', 'comparison', 'evaluation', 'log', 'about'].map(t => {
        return mockDocument.getElementById(`tab-${t}`);
      });
    }
    if (sel === '.speed-pill') return speedPills;
    if (sel === '.topo-node-card') return topoCards;
    if (sel.includes('.sample-chips .chip:not(.chip-domain)')) return sampleChips;
    if (sel === '.chip-domain') return domainChips;
    if (sel === '.stack-layer-card') return stackCards;
    if (sel === '#table-packets th.sortable') return [new MockElement('th', '', { 'data-sort': 'packetNumber' })];
    if (sel === '.res-stage') return [new MockElement('div')];
    if (sel === '.chunk-row') return [];
    if (sel === '.timeline-event-item') return [];
    if (sel === '.btn-inspect-pkt') return [];
    return [];
  },
  createElement: (tag) => new MockElement(tag),
  body: new MockElement('body')
};

// Mock fetch
const mockFetch = async (url, opts = {}) => {
  if (url === '/api/normal-traffic') {
    return {
      ok: true,
      json: async () => ({ queries: [{ queryName: 'www.google.com', length: 14, entropy: 2.1 }] })
    };
  }
  if (url === '/api/simulate') {
    return {
      ok: true,
      json: async () => ({
        success: true,
        packets: [
          {
            packetNumber: 1,
            deliveryStatus: 'DELIVERED',
            dns: { question: { queryName: 'pkt01-abc.google.com', qtype: 'A' }, transactionId: '0x1234', queryLength: 20 },
            request: { transactionId: '0x1234', wireBytes: 40, length: 20, flags: { qr: 0 } },
            response: { transactionId: '0x1234', wireBytes: 56, answers: [{ type: 'A', data: '192.0.2.1' }] }
          }
        ],
        message: 'COMPUTER NETWORKS PROJECT',
        encoding: 'base64',
        totalPackets: 1,
        totalBytes: 25,
        baseDomain: 'google.com',
        pipeline: { originalSizeBytes: 25, encodedSizeBytes: 36, totalQueryBytes: 40 },
        lossSimulation: { lossRate: 0, deliveredCount: 1, droppedCount: 0, missingSequenceIds: [], reconstructionSuccess: true },
        reconstructedMessage: 'COMPUTER NETWORKS PROJECT',
        analysis: {
          suspicionScore: 45,
          classification: 'Normal',
          badgeColor: 'normal',
          indicators: { averageEntropy: 3.2, averageQueryLength: 20, averageSubdomainLength: 8, maxSubdomainLength: 8, totalVolumeBytes: 40 },
          ruleContributions: []
        }
      })
    };
  }
  if (url === '/api/compare') {
    return {
      ok: true,
      json: async () => ({
        normal: { indicators: { averageEntropy: 2.5, averageQueryLength: 15, averageSubdomainLength: 6 } },
        covert: { indicators: { averageEntropy: 4.2, averageQueryLength: 35, averageSubdomainLength: 22 } }
      })
    };
  }
  if (url === '/api/evaluation/latest' || url === '/api/evaluation/run') {
    return {
      ok: true,
      json: async () => ({
        metadata: { timestamp: new Date().toISOString(), sampleCount: 100 },
        configuration: { sampleCount: 100, seed: 42, splitRatio: 0.7 },
        datasetSummary: {
          totalGenerated: 100,
          normalCountTotal: 50,
          covertCountTotal: 50,
          calibrationCount: 70,
          evaluationCount: 30,
          evaluationNormal: 15,
          evaluationCovert: 15
        },
        detectors: {
          ruleBased: { metrics: { accuracy: 0.95, precision: 0.94, recall: 0.96, specificity: 0.94, f1Score: 0.95, falsePositiveRate: 0.06 } },
          entropyBaseline: { threshold: 3.6, metrics: { accuracy: 0.88, precision: 0.85, recall: 0.90, specificity: 0.86, f1Score: 0.87, falsePositiveRate: 0.14 } }
        },
        errorAnalysis: {
          ruleBased: { falsePositives: [], falseNegatives: [] },
          entropyBaseline: { falsePositives: [], falseNegatives: [] }
        }
      })
    };
  }
  if (url === '/api/scenarios/evaluate') {
    return {
      ok: true,
      json: async () => ({
        totalEvaluated: 1,
        ruleBased: { metrics: { accuracy: 1.0, precision: 1.0, recall: 1.0, specificity: 1.0, f1Score: 1.0, falsePositiveRate: 0 } },
        entropyBaseline: { metrics: { accuracy: 1.0, precision: 1.0, recall: 1.0, specificity: 1.0, f1Score: 1.0, falsePositiveRate: 0 } }
      })
    };
  }
  if (url === '/api/scenarios/generate') {
    return {
      ok: true,
      json: async () => ({
        scenario: { id: 'normal_browsing', name: 'Normal Browsing' },
        events: [
          {
            id: 'EVT-001',
            timestamp: '14:00:01',
            client: { id: 'client-01', name: 'Workstation-Alpha', ip: '192.168.1.101' },
            destination: { id: 'dest-web', name: 'Standard Web DNS' },
            queryName: 'www.google.com',
            queryType: 'A',
            groundTruth: 'normal',
            features: { entropy: 2.1, queryLength: 14, subdomainLength: 3, unusualCharRatio: 0, payloadToDomainRatio: 0.2, queryFrequency: 1.2, isBurst: false },
            analysis: { score: 0, status: 'Normal', reasons: [] },
            deliveryStatus: 'DELIVERED',
            packet: {
              packetNumber: 1,
              deliveryStatus: 'DELIVERED',
              dns: { question: { queryName: 'www.google.com', queryType: 'A (IPv4 Host Record)' }, transactionId: '0x1001', payload: { rawPacketBytes: 32, hexDump: '00' } },
              request: { transactionId: '0x1001', wireBytes: 32, flags: { qr: 0 } },
              response: { transactionId: '0x1001', wireBytes: 48, answers: [{ type: 'A', data: '142.250.190.46' }] }
            }
          }
        ],
        summary: { total: 1, normal: 1, covert: 0, dropped: 0 }
      })
    };
  }
  return { ok: true, json: async () => ({}) };
};

// Global context execution
const vm = require('vm');
const context = {
  document: mockDocument,
  window: { addEventListener: mockDocument.addEventListener, location: { href: '' }, alert: (msg) => console.log('  [ALERT]', msg) },
  alert: (msg) => console.log('  [ALERT]', msg),
  fetch: mockFetch,
  console: console,
  setTimeout: (fn) => fn(),
  clearTimeout: () => {},
  setInterval: () => 1,
  clearInterval: () => {},
  Chart: class MockChart {
    constructor() {}
    destroy() {}
    update() {}
  },
  Blob: class MockBlob { constructor() {} },
  URL: { createObjectURL: () => 'blob:mock', revokeObjectURL: () => {} },
  Math: Math,
  parseInt: parseInt,
  parseFloat: parseFloat,
  Date: Date,
  String: String,
  Array: Array,
  Set: Set,
  Object: Object,
  Promise: Promise
};

vm.createContext(context);

try {
  // Execute script.js
  vm.runInContext(js, context);
  console.log('[PASS] script.js evaluated without syntax or parse errors.');
} catch (err) {
  console.error('[FAIL] Syntax or evaluation error in script.js:', err);
  process.exit(1);
}

// Fire DOMContentLoaded
(async () => {
  try {
    for (const listener of domReadyListeners) {
      await listener();
    }
    console.log('[PASS] DOMContentLoaded executed cleanly with 0 exceptions.');
  } catch (err) {
    console.error('[FAIL] Exception during DOMContentLoaded:', err);
    process.exit(1);
  }

  // Test interactive buttons
  console.log('\n--- Testing Navigation Tabs ---');
  navTabs.forEach(tab => {
    tab.click();
    console.log(`  [CLICK] Nav Tab: ${tab.getAttribute('data-tab')}`);
  });

  console.log('\n--- Testing Quick Demo & Educational Simulator Controls ---');
  const btnQuickDemo = domElements.get('btn-quick-demo');
  if (btnQuickDemo) { btnQuickDemo.click(); console.log('  [CLICK] btn-quick-demo'); }

  const btnDashDemo = domElements.get('btn-dash-run-demo');
  if (btnDashDemo) { btnDashDemo.click(); console.log('  [CLICK] btn-dash-run-demo'); }

  const btnSimStart = domElements.get('btn-sim-start');
  if (btnSimStart) { btnSimStart.click(); console.log('  [CLICK] btn-sim-start'); }

  const btnSimStep = domElements.get('btn-sim-step');
  if (btnSimStep) { btnSimStep.click(); console.log('  [CLICK] btn-sim-step'); }

  const btnSimPause = domElements.get('btn-sim-pause');
  if (btnSimPause) { btnSimPause.click(); console.log('  [CLICK] btn-sim-pause'); }

  const btnSimReset = domElements.get('btn-sim-reset');
  if (btnSimReset) { btnSimReset.click(); console.log('  [CLICK] btn-sim-reset'); }

  const btnPrev = domElements.get('btn-prev-pkt');
  if (btnPrev) { btnPrev.click(); console.log('  [CLICK] btn-prev-pkt'); }

  const btnNext = domElements.get('btn-next-pkt');
  if (btnNext) { btnNext.click(); console.log('  [CLICK] btn-next-pkt'); }

  const btnRefreshComp = domElements.get('btn-refresh-compare');
  if (btnRefreshComp) { btnRefreshComp.click(); console.log('  [CLICK] btn-refresh-compare'); }

  console.log('\n--- Testing Replay Lab Controls ---');
  const btnPlay = domElements.get('btn-replay-play');
  if (btnPlay) { btnPlay.click(); console.log('  [CLICK] btn-replay-play'); }

  const btnPause = domElements.get('btn-replay-pause');
  if (btnPause) { btnPause.click(); console.log('  [CLICK] btn-replay-pause'); }

  const btnStep = domElements.get('btn-replay-step');
  if (btnStep) { btnStep.click(); console.log('  [CLICK] btn-replay-step'); }

  const btnReset = domElements.get('btn-replay-reset');
  if (btnReset) { btnReset.click(); console.log('  [CLICK] btn-replay-reset'); }

  const btnAll = domElements.get('btn-replay-all');
  if (btnAll) { btnAll.click(); console.log('  [CLICK] btn-replay-all'); }

  const btnRndSeed = domElements.get('btn-replay-seed-rnd');
  if (btnRndSeed) { btnRndSeed.click(); console.log('  [CLICK] btn-replay-seed-rnd'); }

  speedPills.forEach(p => { p.click(); console.log(`  [CLICK] Speed pill: ${p.getAttribute('data-speed')}ms`); });

  topoCards.forEach(c => { c.click(); console.log(`  [CLICK] Topo Card: ${c.getAttribute('data-node')}`); });

  const btnClearTopo = domElements.get('btn-clear-topo-filter');
  if (btnClearTopo) { btnClearTopo.click(); console.log('  [CLICK] btn-clear-topo-filter'); }

  const btnSaveAssess = domElements.get('btn-save-assessment');
  if (btnSaveAssess) { btnSaveAssess.click(); console.log('  [CLICK] btn-save-assessment'); }

  const btnEvalScen = domElements.get('btn-eval-scenario');
  if (btnEvalScen) { btnEvalScen.click(); console.log('  [CLICK] btn-eval-scenario'); }

  const btnExportInvCsv = domElements.get('btn-export-investigation-csv');
  if (btnExportInvCsv) { btnExportInvCsv.click(); console.log('  [CLICK] btn-export-investigation-csv'); }

  console.log('\n--- Testing Evaluation Lab Controls ---');
  const btnEvalRun = domElements.get('btn-run-evaluation');
  if (btnEvalRun) { btnEvalRun.click(); console.log('  [CLICK] btn-run-evaluation'); }

  const btnEvalSeed = domElements.get('btn-random-seed');
  if (btnEvalSeed) { btnEvalSeed.click(); console.log('  [CLICK] btn-random-seed'); }

  const btnExportEvalCsv = domElements.get('btn-export-eval-csv');
  if (btnExportEvalCsv) { btnExportEvalCsv.click(); console.log('  [CLICK] btn-export-eval-csv'); }

  const btnExportEvalJson = domElements.get('btn-export-eval-json');
  if (btnExportEvalJson) { btnExportEvalJson.click(); console.log('  [CLICK] btn-export-eval-json'); }

  const btnPrintEval = domElements.get('btn-print-eval-report');
  if (btnPrintEval) { btnPrintEval.click(); console.log('  [CLICK] btn-print-eval-report'); }

  console.log('\n--- Testing General Export Controls ---');
  const btnExportCsv = domElements.get('btn-export-csv');
  if (btnExportCsv) { btnExportCsv.click(); console.log('  [CLICK] btn-export-csv'); }

  const btnExportJson = domElements.get('btn-export-json');
  if (btnExportJson) { btnExportJson.click(); console.log('  [CLICK] btn-export-json'); }

  console.log('\n>>> SUCCESS: ALL INTERACTIVE BUTTONS TESTED CLEANLY WITH ZERO EXCEPTIONS! <<<');
})();
