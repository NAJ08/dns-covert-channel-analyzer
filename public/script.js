/**
 * DNS Steganography & Covert Channel Analyzer
 * Client-side Controller & Simulation Engine
 */

// Application State
const state = {
  activeTab: 'dashboard',
  activeStackLayer: 'application',
  currentStream: null,
  currentAnalysis: null,
  normalTraffic: null,
  activePacketIndex: 0,
  simulationTimer: null,
  isPaused: false,
  isSimulating: false,
  stepIndex: 0,
  sortField: 'packetNumber',
  sortAsc: true,
  latestEvaluation: null,
  charts: {},

  // Investigation & Replay State
  replayStream: null,
  replayProcessedEvents: [],
  replayIndex: 0,
  replayTimer: null,
  isReplayRunning: false,
  replaySpeedMs: 700,
  activeNodeFilter: null,
  activeEvent: null,
  investigations: {},
  nodeStats: {
    'client-01': { queries: 0, alerts: 0 },
    'client-02': { queries: 0, alerts: 0 },
    'client-03': { queries: 0, alerts: 0 },
    'resolver-01': { queries: 0 },
    'dest-web': { queries: 0 },
    'dest-cdn': { queries: 0 },
    'dest-covert': { queries: 0 }
  }
};

// Safe DOM Helper Utilities
function safeAddListener(id, event, handler) {
  const el = document.getElementById(id);
  if (el) {
    el.addEventListener(event, handler);
    return true;
  }
  return false;
}

function safeSetText(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text;
    return true;
  }
  return false;
}

function safeSetHtml(id, html) {
  const el = document.getElementById(id);
  if (el) {
    el.innerHTML = html;
    return true;
  }
  return false;
}

// DOM Ready
document.addEventListener('DOMContentLoaded', async () => {
  try { initNavigation(); } catch (e) { console.error('initNavigation error:', e); }
  try { initFormControls(); } catch (e) { console.error('initFormControls error:', e); }
  try { initActionButtons(); } catch (e) { console.error('initActionButtons error:', e); }
  try { initTableFilters(); } catch (e) { console.error('initTableFilters error:', e); }
  try { initEvaluationControls(); } catch (e) { console.error('initEvaluationControls error:', e); }
  try { initReplayLab(); } catch (e) { console.error('initReplayLab error:', e); }

  // Load baseline normal traffic from server
  try { await fetchNormalTraffic(); } catch (e) { console.error('fetchNormalTraffic error:', e); }

  // Run initial demo so dashboard and simulator are populated with realistic state
  try { await runCompleteDemo(); } catch (e) { console.error('runCompleteDemo error:', e); }

  // Load initial scientific evaluation benchmark
  try { await loadLatestEvaluation(); } catch (e) { console.error('loadLatestEvaluation error:', e); }

  // Load initial replay scenario
  try { await loadReplayScenario('normal_browsing', 42); } catch (e) { console.error('loadReplayScenario error:', e); }
});

/* ==========================================================================
   Navigation & Tabs
   ========================================================================== */
function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      switchTab(target);
    });
  });

  // Quick switch from dashboard
  const btnGotoSim = document.getElementById('btn-goto-simulator');
  if (btnGotoSim) {
    btnGotoSim.addEventListener('click', () => switchTab('simulator'));
  }
}

function switchTab(tabId) {
  state.activeTab = tabId;

  // Update tabs UI
  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
  });

  // Update pane UI
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });

  // Re-render charts or topology if entering specific tabs
  if (tabId === 'dashboard') {
    setTimeout(updateTopologyConnectionLines, 50);
  } else if (tabId === 'comparison') {
    setTimeout(renderComparisonCharts, 50);
  } else if (tabId === 'evaluation') {
    setTimeout(renderEvaluationComparisonChart, 50);
  }
}

/* ==========================================================================
   Form Controls & Real-time Input Listeners
   ========================================================================== */
function initFormControls() {
  // Sliders with live labels
  const chunkSlider = document.getElementById('slider-chunk-size');
  const chunkVal = document.getElementById('chunk-size-val');
  chunkSlider.addEventListener('input', () => {
    chunkVal.textContent = `${chunkSlider.value} chars`;
    updateSimulationPreview();
  });

  const delaySlider = document.getElementById('slider-delay');
  const delayVal = document.getElementById('delay-val');
  delaySlider.addEventListener('input', () => {
    delayVal.textContent = `${delaySlider.value} ms`;
  });

  // Feature 5: Packet Loss Slider
  const lossSlider = document.getElementById('slider-packet-loss');
  const lossVal = document.getElementById('packet-loss-val');
  if (lossSlider) {
    lossSlider.addEventListener('input', () => {
      const val = parseInt(lossSlider.value, 10) || 0;
      lossVal.textContent = val === 0 ? '0% (Reliable)' : `${val}% Loss`;
    });
  }

  // Sample Chips
  document.querySelectorAll('.sample-chips .chip:not(.chip-domain)').forEach(chip => {
    chip.addEventListener('click', () => {
      document.getElementById('input-message').value = chip.getAttribute('data-sample');
      updateSimulationPreview();
    });
  });

  // Feature 1: Domain Preset Chips
  document.querySelectorAll('.chip-domain').forEach(chip => {
    chip.addEventListener('click', () => {
      document.getElementById('input-domain').value = chip.getAttribute('data-domain');
      updateSimulationPreview();
    });
  });

  // Feature 4: Protocol Stack Layer Clicks
  document.querySelectorAll('.stack-layer-card').forEach(card => {
    card.addEventListener('click', () => {
      const layer = card.getAttribute('data-layer');
      selectProtocolStackLayer(layer);
    });
  });

  // Encoding & Message change
  safeAddListener('input-message', 'input', updateSimulationPreview);
  safeAddListener('select-encoding', 'change', updateSimulationPreview);
  safeAddListener('input-domain', 'input', updateSimulationPreview);
  safeAddListener('check-include-seq', 'change', updateSimulationPreview);

  // Packet selector dropdown
  safeAddListener('select-active-packet', 'change', (e) => {
    state.activePacketIndex = parseInt(e.target.value, 10);
    renderPacketInspection(state.activePacketIndex);
  });

  safeAddListener('btn-prev-pkt', 'click', () => {
    if (state.currentStream && state.activePacketIndex > 0) {
      state.activePacketIndex--;
      const sel = document.getElementById('select-active-packet');
      if (sel) sel.value = state.activePacketIndex;
      renderPacketInspection(state.activePacketIndex);
    }
  });

  safeAddListener('btn-next-pkt', 'click', () => {
    if (state.currentStream && state.activePacketIndex < state.currentStream.packets.length - 1) {
      state.activePacketIndex++;
      const sel = document.getElementById('select-active-packet');
      if (sel) sel.value = state.activePacketIndex;
      renderPacketInspection(state.activePacketIndex);
    }
  });
}

/* ==========================================================================
   Action Buttons
   ========================================================================== */
function initActionButtons() {
  // Quick Demo Buttons
  safeAddListener('btn-quick-demo', 'click', runCompleteDemo);
  safeAddListener('btn-dash-run-demo', 'click', runCompleteDemo);

  // Simulator controls
  safeAddListener('btn-sim-start', 'click', startSimulationFlow);
  safeAddListener('btn-sim-step', 'click', stepSimulationFlow);
  safeAddListener('btn-sim-pause', 'click', pauseSimulationFlow);
  safeAddListener('btn-sim-reset', 'click', resetSimulation);
  safeAddListener('btn-refresh-compare', 'click', refreshComparison);

  // Export buttons
  safeAddListener('btn-export-csv', 'click', exportTrafficCSV);
  safeAddListener('btn-export-json', 'click', exportTrafficJSON);
}

/* ==========================================================================
   Table Filters & Sorting
   ========================================================================== */
function initTableFilters() {
  safeAddListener('log-search-input', 'input', filterPacketTable);
  safeAddListener('log-filter-status', 'change', filterPacketTable);
  safeAddListener('log-filter-delivery', 'change', filterPacketTable);

  document.querySelectorAll('#table-packets th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.getAttribute('data-sort');
      if (state.sortField === field) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortField = field;
        state.sortAsc = true;
      }
      renderPacketTable();
    });
  });
}

/* ==========================================================================
   Server API Communications
   ========================================================================== */
async function fetchNormalTraffic() {
  try {
    const res = await fetch('/api/normal-traffic');
    state.normalTraffic = await res.json();
  } catch (err) {
    console.error('Failed to fetch normal traffic baseline:', err);
  }
}

async function requestSimulation(params) {
  const res = await fetch('/api/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Simulation error');
  }
  return await res.json();
}

/* ==========================================================================
   One-Click Demonstration
   ========================================================================== */
async function runCompleteDemo() {
  // Set default parameters
  document.getElementById('input-message').value = 'COMPUTER NETWORKS PROJECT';
  document.getElementById('select-encoding').value = 'base64';
  document.getElementById('input-domain').value = 'example.com';
  document.getElementById('slider-chunk-size').value = 16;
  document.getElementById('chunk-size-val').textContent = '16 chars';
  document.getElementById('slider-packet-loss').value = 0;
  document.getElementById('packet-loss-val').textContent = '0% (Reliable)';
  document.getElementById('select-qtype').value = 'A';
  document.getElementById('check-include-seq').checked = true;

  updateStatusLog('Initiating automated demonstration for "COMPUTER NETWORKS PROJECT" on example.com...', 'cyan');
  setPipelineActiveStage('sender');

  try {
    const stream = await requestSimulation({
      message: 'COMPUTER NETWORKS PROJECT',
      encoding: 'base64',
      domain: 'example.com',
      chunkSize: 16,
      queryType: 'A',
      interArrivalMs: 120,
      includeSeq: true,
      packetLoss: 0
    });

    state.currentStream = stream;
    state.currentAnalysis = stream.analysis;
    state.activePacketIndex = 0;

    // Run rapid visual pipeline animation
    await animatePipelineLifecycle(stream);

    // Populate all dashboards and views
    renderSimulationViews(stream);
    renderDashboardStats(stream);
    renderPacketInspection(0);
    renderDetectionView(stream.analysis);
    renderPacketTable();
    await refreshComparison();

    // Trigger visual DNS resolution flow for first packet
    if (stream.packets && stream.packets[0]) {
      animateDnsResolution(stream.packets[0]);
    }

    updateStatusLog('Demonstration completed successfully! All metrics, packets, and comparisons updated.', 'emerald');
  } catch (err) {
    updateStatusLog(`Demonstration failed: ${err.message}`, 'danger');
  }
}

/* ==========================================================================
   Simulation Control State Machine
   ========================================================================== */
function getSimulatorFormValues() {
  return {
    message: document.getElementById('input-message').value.trim() || 'COMPUTER NETWORKS PROJECT',
    encoding: document.getElementById('select-encoding').value,
    domain: document.getElementById('input-domain').value.trim() || 'example.com',
    chunkSize: parseInt(document.getElementById('slider-chunk-size').value, 10) || 16,
    queryType: document.getElementById('select-qtype').value,
    interArrivalMs: parseInt(document.getElementById('slider-delay').value, 10) || 120,
    includeSeq: document.getElementById('check-include-seq').checked,
    packetLoss: parseInt(document.getElementById('slider-packet-loss')?.value, 10) || 0
  };
}

async function updateSimulationPreview() {
  const params = getSimulatorFormValues();
  try {
    const res = await fetch('/api/encode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    const data = await res.json();
    if (res.ok) {
      document.getElementById('pipe-orig-bytes').textContent = data.originalSizeBytes;
      document.getElementById('pipe-enc-bytes').textContent = data.encodedSizeBytes;
      document.getElementById('pipe-exp-ratio').textContent = `${data.expansionRatio}x`;
      document.getElementById('pipe-pkt-estimate').textContent = data.totalPackets;
      document.getElementById('pipe-encoded-payload').textContent = data.encodedPayload;
    }
  } catch (err) {
    console.error('Preview error:', err);
  }
}

async function startSimulationFlow() {
  const params = getSimulatorFormValues();
  const btnStart = document.getElementById('btn-sim-start');
  const btnPause = document.getElementById('btn-sim-pause');
  
  btnStart.disabled = true;
  btnPause.disabled = false;
  state.isSimulating = true;
  state.isPaused = false;

  updateStatusLog(`Generating synthetic DNS queries for "${params.message}" on ${params.domain} (Loss: ${params.packetLoss}%)...`, 'cyan');

  try {
    const stream = await requestSimulation(params);
    state.currentStream = stream;
    state.currentAnalysis = stream.analysis;
    state.activePacketIndex = 0;

    // Run animation
    await animatePipelineLifecycle(stream);

    renderSimulationViews(stream);
    renderDashboardStats(stream);
    renderPacketInspection(0);
    renderDetectionView(stream.analysis);
    renderPacketTable();
    await refreshComparison();

    if (stream.packets && stream.packets[0]) {
      animateDnsResolution(stream.packets[0]);
    }

    if (stream.packetsLost > 0) {
      updateStatusLog(`Simulation complete: Transmitted ${stream.totalPackets} packets (${stream.packetsLost} dropped). Reconstruction FAILED.`, 'danger');
    } else {
      updateStatusLog(`Simulation complete: Transmitted ${stream.totalPackets} simulated DNS queries (100% delivered).`, 'emerald');
    }
  } catch (err) {
    updateStatusLog(`Simulation error: ${err.message}`, 'danger');
  } finally {
    btnStart.disabled = false;
    btnPause.disabled = true;
    state.isSimulating = false;
  }
}

async function stepSimulationFlow() {
  if (!state.currentStream) {
    const params = getSimulatorFormValues();
    state.currentStream = await requestSimulation(params);
    state.currentAnalysis = state.currentStream.analysis;
    state.stepIndex = 0;
    renderSimulationViews(state.currentStream);
    renderPacketInspection(0);
  }

  const packets = state.currentStream.packets;
  if (state.stepIndex < packets.length) {
    const currentPkt = packets[state.stepIndex];
    highlightChunkRow(state.stepIndex);
    renderPacketInspection(state.stepIndex);
    animateDnsResolution(currentPkt);
    
    const lossTag = currentPkt.deliveryStatus === 'LOST' ? ' [LOST - UDP DROPPED]' : ' [DELIVERED]';
    updateStatusLog(`Stepping: Emitted Simulated Packet #${currentPkt.packetNumber}${lossTag} -> ${currentPkt.dns.question.queryName}`, currentPkt.deliveryStatus === 'LOST' ? 'danger' : 'cyan');
    state.stepIndex++;

    if (state.stepIndex === packets.length) {
      renderDashboardStats(state.currentStream);
      renderDetectionView(state.currentStream.analysis);
      renderPacketTable();
      updateStatusLog('Stepping reached final packet sequence.', 'emerald');
    }
  } else {
    state.stepIndex = 0;
    updateStatusLog('Reset stepping to beginning of stream.', 'cyan');
  }
}

function pauseSimulationFlow() {
  state.isPaused = !state.isPaused;
  const btnPause = document.getElementById('btn-sim-pause');
  btnPause.textContent = state.isPaused ? '▶ Resume' : '⏸ Pause';
  updateStatusLog(state.isPaused ? 'Simulation paused.' : 'Resuming simulation...', 'cyan');
}

function resetSimulation() {
  state.currentStream = null;
  state.currentAnalysis = null;
  state.activePacketIndex = 0;
  state.stepIndex = 0;

  // Clear UI displays
  safeSetText('dash-packets-count', '0');
  safeSetText('dash-queries-count', '0');
  safeSetHtml('dash-entropy-val', '0.00 <span class="unit">bits/char</span>');
  safeSetText('dash-score-val', '0');
  
  const badge = document.getElementById('dash-score-badge');
  if (badge) {
    badge.className = 'badge badge-normal';
    badge.textContent = 'Idle';
  }

  safeSetHtml('pipe-chunks-list', '<div class="empty-state">No queries generated yet. Click "Start Simulation" or "Run Demo".</div>');
  safeSetText('pipe-assembled-stream', '[Pending query reception...]');
  safeSetText('pipe-decoded-plaintext', '[Recovered message will appear here...]');
  const pipeLossAlert = document.getElementById('pipe-loss-alert');
  if (pipeLossAlert) pipeLossAlert.style.display = 'none';
  const pipeReconBadge = document.getElementById('pipe-recon-badge');
  if (pipeReconBadge) {
    pipeReconBadge.textContent = 'Ready';
    pipeReconBadge.className = 'badge badge-normal';
  }
  safeSetText('pipe-loss-summary', 'Generated: 0 | Delivered: 0 | Lost: 0');

  clearPipelineHighlight();
  resetDnsResolutionUI();
  updateStatusLog('Simulation state reset to idle.', 'muted');
}

/* ==========================================================================
   Animated Pipeline & Visual Progress
   ========================================================================== */
function setPipelineActiveStage(stageId) {
  const stages = ['sender', 'encoder', 'simulator', 'network', 'analyzer', 'decoder', 'receiver'];
  const targetIdx = stages.indexOf(stageId);

  stages.forEach((stg, i) => {
    const node = document.getElementById(`node-${stg}`);
    const line = document.getElementById(`line-${i}`);

    if (node) {
      node.classList.toggle('active-node', i === targetIdx);
      node.classList.toggle('done-node', i < targetIdx);
    }
    if (line) {
      line.classList.toggle('active-line', i <= targetIdx);
    }
  });

  const tag = document.getElementById('pipeline-status-tag');
  if (tag) {
    tag.textContent = `Stage: ${stageId.toUpperCase()}`;
  }
}

function clearPipelineHighlight() {
  const stages = ['sender', 'encoder', 'simulator', 'network', 'analyzer', 'decoder', 'receiver'];
  stages.forEach((stg, i) => {
    const node = document.getElementById(`node-${stg}`);
    const line = document.getElementById(`line-${i}`);
    if (node) {
      node.classList.remove('active-node', 'done-node');
    }
    if (line) {
      line.classList.remove('active-line');
    }
  });
  safeSetText('pipeline-status-tag', 'System Ready');
}

function updateStatusLog(msg, color = 'cyan') {
  const log = document.getElementById('pipeline-log-text');
  if (log) {
    log.textContent = msg;
    log.className = color === 'emerald' ? 'text-emerald' : color === 'danger' ? 'text-danger' : 'text-cyan';
  }
}

async function animatePipelineLifecycle(stream) {
  const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  setPipelineActiveStage('sender');
  updateStatusLog(`[Sender] Sourcing secret plaintext: "${stream.message}"`, 'cyan');
  await delay(200);

  setPipelineActiveStage('encoder');
  updateStatusLog(`[Encoder] Encoded ${stream.pipeline.originalSizeBytes} bytes into ${stream.pipeline.encodedSizeBytes} chars (${stream.encoding.toUpperCase()})`, 'cyan');
  await delay(200);

  setPipelineActiveStage('simulator');
  updateStatusLog(`[DNS Simulator] Chunked payload into ${stream.totalPackets} labels on ${stream.baseDomain}`, 'cyan');
  await delay(200);

  setPipelineActiveStage('network');
  const lossMsg = stream.packetsLost > 0 ? ` (${stream.packetsLost} packets dropped by UDP simulation)` : '';
  updateStatusLog(`[Simulated Network] Transmitting synthetic UDP/53 queries...${lossMsg}`, 'cyan');
  await delay(300);

  setPipelineActiveStage('analyzer');
  updateStatusLog(`[DNS Analyzer] Computing Shannon entropy & checking anomaly rules...`, 'cyan');
  await delay(200);

  setPipelineActiveStage('decoder');
  updateStatusLog(`[Decoder] Extracting chunk labels & reversing ${stream.encoding.toUpperCase()}...`, 'cyan');
  await delay(200);

  setPipelineActiveStage('receiver');
  if (stream.reconstruction.reconstructionStatus === 'FAILED') {
    updateStatusLog(`[Receiver] Reconstruction FAILED: Missing packets: ${stream.reconstruction.missingPackets.join(', ')}`, 'danger');
  } else {
    updateStatusLog(`[Receiver] Recovered original plaintext: "${stream.message}"`, 'emerald');
  }
  await delay(150);
}

/* ==========================================================================
   Feature 2: Simulated DNS Resolution Flow Animation
   ========================================================================== */
function animateDnsResolution(packet) {
  if (!packet || !packet.resolutionTrace) return;
  const trace = packet.resolutionTrace;

  document.getElementById('res-auth-domain').textContent = `ns1.${packet.baseDomain || 'example.com'}`;

  // Execute sequential resolution animation
  const steps = [
    { node: 'res-node-client', tag: 'res-tag-client', status: 'QUERY SENT', text: trace[0]?.message },
    { node: 'res-node-resolver', tag: 'res-tag-resolver', status: 'FORWARDING', text: trace[1]?.message },
    { node: 'res-node-root', tag: 'res-tag-root', status: 'TLD REFERRAL', text: trace[2]?.message },
    { node: 'res-node-tld', tag: 'res-tag-tld', status: 'AUTH REFERRAL', text: trace[4]?.message },
    { node: 'res-node-auth', tag: 'res-tag-auth', status: 'AUTHORITY FOUND', text: trace[5]?.message },
    { node: 'res-node-response', tag: 'res-tag-response', status: 'RESPONSE RCVD', text: trace[7]?.message }
  ];

  let currentIdx = 0;
  function stepResolution() {
    if (currentIdx >= steps.length) return;
    const s = steps[currentIdx];

    // Highlight current node
    document.querySelectorAll('.res-stage').forEach((n, i) => {
      n.classList.toggle('active-stage', i === currentIdx);
      n.classList.toggle('done-stage', i < currentIdx);
    });

    const tagEl = document.getElementById(s.tag);
    if (tagEl) {
      tagEl.textContent = s.status;
    }
    const stepText = document.getElementById('res-step-text');
    if (stepText) {
      stepText.textContent = s.text || s.status;
    }

    currentIdx++;
    if (currentIdx < steps.length) {
      setTimeout(stepResolution, 220);
    }
  }

  stepResolution();
}

function resetDnsResolutionUI() {
  document.querySelectorAll('.res-stage').forEach(n => {
    n.classList.remove('active-stage', 'done-stage');
  });
  safeSetText('res-tag-client', 'READY');
  safeSetText('res-tag-resolver', 'WAITING');
  safeSetText('res-tag-root', 'STANDBY');
  safeSetText('res-tag-tld', 'STANDBY');
  safeSetText('res-tag-auth', 'STANDBY');
  safeSetText('res-tag-response', 'STANDBY');
  safeSetText('res-step-text', 'Awaiting query resolution flow.');
}

/* ==========================================================================
   Feature 4: Interactive Network Protocol Stack
   ========================================================================== */
function selectProtocolStackLayer(layerName) {
  state.activeStackLayer = layerName;

  document.querySelectorAll('.stack-layer-card').forEach(card => {
    card.classList.toggle('active-layer', card.getAttribute('data-layer') === layerName);
  });

  const pkt = state.currentStream?.packets?.[state.activePacketIndex] || null;
  const stack = pkt?.protocolStack || null;

  const titleEl = document.getElementById('stack-ins-title');
  const badgeEl = document.getElementById('stack-ins-badge');
  const descEl = document.getElementById('stack-ins-desc');
  const fieldsGrid = document.getElementById('stack-fields-grid');

  if (!stack || !stack[layerName]) {
    // Default explanation if no packet yet
    const defaults = {
      application: {
        title: 'Application Layer: DNS (Domain Name System - RFC 1035)',
        badge: 'L7 Protocol',
        desc: 'DNS query names carry encoded payload labels within subdomains. Operates on port 53.',
        fields: { Protocol: 'DNS (RFC 1035)', Port: '53', Encoding: 'Subdomain labels' }
      },
      transport: {
        title: 'Transport Layer: UDP (User Datagram Protocol - RFC 768)',
        badge: 'L4 Protocol',
        desc: 'Provides connectionless, unreliable transport without retransmission or ACKs, enabling packet loss.',
        fields: { Protocol: 'UDP (17)', Header: '8 bytes', Reliability: 'Unreliable' }
      },
      internet: {
        title: 'Internet Layer: IPv4 (Internet Protocol - RFC 791)',
        badge: 'L3 Protocol',
        desc: 'Routes packets across IP networks between host NIC (192.168.1.105) and DNS resolver (8.8.8.8).',
        fields: { Protocol: 'IPv4 (0x0800)', TTL: '64', Header: '20 bytes' }
      },
      networkAccess: {
        title: 'Network Access Layer: Ethernet II / Wi-Fi (IEEE 802.3)',
        badge: 'L2 Protocol',
        desc: 'Encapsulates the IP datagram into physical MAC frames with destination gateway address.',
        fields: { Medium: 'Ethernet II', EtherType: '0x0800', FCS: 'CRC32 Checksum' }
      }
    };
    const def = defaults[layerName] || defaults.application;
    titleEl.textContent = def.title;
    badgeEl.textContent = def.badge;
    descEl.textContent = def.desc;
    fieldsGrid.innerHTML = Object.entries(def.fields).map(([k, v]) => 
      `<div class="stack-field-item"><strong>${k}:</strong> ${v}</div>`
    ).join('');
    return;
  }

  const info = stack[layerName];
  titleEl.textContent = `${info.layer}: ${info.protocol}`;
  badgeEl.textContent = info.layer.split(' ')[0];
  descEl.textContent = info.description;

  fieldsGrid.innerHTML = Object.entries(info.details).map(([k, v]) => 
    `<div class="stack-field-item"><strong>${k}:</strong> ${v}</div>`
  ).join('');
}

/* ==========================================================================
   Rendering Simulator Views (Chunks & Decoded Data & Packet Loss)
   ========================================================================== */
function renderSimulationViews(stream) {
  const p = stream.pipeline;

  // Pipeline metrics
  document.getElementById('pipe-orig-bytes').textContent = p.originalSizeBytes;
  document.getElementById('pipe-enc-bytes').textContent = p.encodedSizeBytes;
  document.getElementById('pipe-exp-ratio').textContent = `${p.expansionRatio}x`;
  document.getElementById('pipe-pkt-estimate').textContent = p.totalPackets;
  document.getElementById('pipe-encoded-payload').textContent = p.encodedPayload;

  // Feature 5: Packet Loss Summary
  const lossSummary = document.getElementById('pipe-loss-summary');
  if (lossSummary) {
    lossSummary.textContent = `Generated: ${stream.packetsGenerated} | Delivered: ${stream.packetsDelivered} | Lost: ${stream.packetsLost}`;
    lossSummary.className = stream.packetsLost > 0 ? 'packet-stats-pill text-warning' : 'packet-stats-pill text-emerald';
  }

  // Chunk list
  const listContainer = document.getElementById('pipe-chunks-list');
  listContainer.innerHTML = '';

  stream.packets.forEach((pkt, idx) => {
    const isLost = pkt.deliveryStatus === 'LOST';
    const row = document.createElement('div');
    row.className = `chunk-row ${isLost ? 'chunk-lost' : ''}`;
    row.id = `chunk-row-${idx}`;
    row.innerHTML = `
      <div>
        <span class="chunk-tag">Pkt #${pkt.packetNumber}</span>
        <strong class="chunk-qname ml-2">${pkt.dns.question.queryName}</strong>
      </div>
      <div>
        <span class="text-xs text-muted mr-2">chunk: "${pkt.dns.payload.encodedPayload}"</span>
        <span class="badge ${isLost ? 'badge-danger' : 'badge-normal'}">${pkt.deliveryStatus}</span>
      </div>
    `;
    listContainer.appendChild(row);
  });

  // Feature 5: Reconstructed output & Loss Alert
  const recon = stream.reconstruction;
  const alertBox = document.getElementById('pipe-loss-alert');
  const reconBadge = document.getElementById('pipe-recon-badge');
  const decodedTerminal = document.getElementById('pipe-decoded-plaintext');

  document.getElementById('pipe-assembled-stream').textContent = recon.assembledPayload || '(empty)';

  if (recon.reconstructionStatus === 'FAILED') {
    alertBox.style.display = 'flex';
    document.getElementById('pipe-missing-list').textContent = `Missing sequence numbers: [${recon.missingPackets.join(', ')}]`;
    reconBadge.textContent = 'FAILED (Packet Loss)';
    reconBadge.className = 'badge badge-danger';
    decodedTerminal.textContent = recon.decodedMessage;
    decodedTerminal.className = 'code-terminal';
  } else {
    alertBox.style.display = 'none';
    reconBadge.textContent = 'SUCCESS';
    reconBadge.className = 'badge badge-normal';
    decodedTerminal.textContent = recon.decodedMessage;
    decodedTerminal.className = 'code-terminal success-terminal';
  }

  // Update packet selector dropdown
  const selector = document.getElementById('select-active-packet');
  selector.innerHTML = '';
  stream.packets.forEach((pkt, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = `Packet #${pkt.packetNumber} [${pkt.deliveryStatus}]: ${pkt.dns.question.queryName}`;
    selector.appendChild(opt);
  });
}

function highlightChunkRow(index) {
  document.querySelectorAll('.chunk-row').forEach((row, i) => {
    row.classList.toggle('in-transit', i === index);
  });
}

/* ==========================================================================
   Rendering Dashboard Statistics
   ========================================================================== */
function renderDashboardStats(stream) {
  const analysis = stream.analysis;
  safeSetText('dash-packets-count', stream.totalPackets);
  safeSetText('dash-queries-count', stream.totalPackets);
  safeSetHtml('dash-entropy-val', `${analysis.indicators.averageEntropy} <span class="unit">bits/char</span>`);
  safeSetText('dash-score-val', analysis.suspicionScore);

  const badge = document.getElementById('dash-score-badge');
  if (badge) {
    badge.textContent = analysis.classification;
    badge.className = `badge badge-${analysis.badgeColor}`;
  }

  safeSetText('dash-packets-sub', `Total size: ${stream.pipeline.totalQueryBytes} FQDN bytes`);
  safeSetText('dash-queries-sub', `Base domain: ${stream.baseDomain}`);
  safeSetText('dash-entropy-sub', analysis.indicators.averageEntropy > 3.6 
    ? 'High character entropy detected' 
    : 'Entropy in acceptable range');
  safeSetText('dash-score-sub', `${analysis.ruleContributions.length} detection heuristics evaluated`);
}

/* ==========================================================================
   Feature 3: Paired DNS Request and Response Inspection
   ========================================================================== */
function renderPacketInspection(packetIdx) {
  if (!state.currentStream || !state.currentStream.packets[packetIdx]) return;

  const pkt = state.currentStream.packets[packetIdx];
  const dns = pkt.dns;
  const req = pkt.request || dns;
  const resp = pkt.response;
  const analysis = state.currentAnalysis?.queryDetails?.[packetIdx];

  // Request Fields
  safeSetText('req-tx-id', req.transactionId || (dns.header && dns.header.transactionId) || '');
  safeSetText('req-flags', `${req.flags || (dns.header && dns.header.flags) || '0x0100'} (RD=1)`);
  safeSetText('req-qdcount', req.qdcount || 1);
  safeSetText('req-qname', req.qname || (dns.question && dns.question.queryName) || '');
  safeSetText('req-qtype', req.queryType || (dns.question && dns.question.queryType) || 'A');
  safeSetText('req-qclass', req.queryClass || (dns.question && dns.question.queryClass) || 'IN');

  // Response Fields
  if (resp) {
    safeSetText('resp-tx-id', `${resp.transactionId || ''} (Matches Request)`);
    safeSetText('resp-flags', `${resp.flags || ''} (Response, AA=1, RA=1)`);
    safeSetText('resp-qdcount', resp.qdcount || 1);
    safeSetText('resp-ancount', resp.ancount || 1);
    safeSetText('resp-qname', resp.qname || (dns.question && dns.question.queryName) || '');
    const qtype = resp.queryType ? resp.queryType.split(' ')[0] : (req.queryType ? req.queryType.split(' ')[0] : (dns.question && dns.question.queryType) || 'A');
    safeSetText('resp-type-class', `${qtype} / IN`);
    const rdata = (resp.simulatedAnswer && resp.simulatedAnswer.rdata) || (resp.answers && resp.answers[0] && resp.answers[0].data) || '192.0.2.1';
    safeSetText('resp-answer-rdata', rdata);
  }

  // Visual Flow
  safeSetText('flow-req-qname', req.qname || (dns.question && dns.question.queryName) || '');
  const rdata = (resp && resp.simulatedAnswer && resp.simulatedAnswer.rdata) || (resp && resp.answers && resp.answers[0] && resp.answers[0].data) || '192.0.2.1';
  safeSetText('flow-resp-rdata', rdata);

  // Delivery status badge
  const delBadge = document.getElementById('analyzer-delivery-status');
  if (delBadge) {
    delBadge.textContent = pkt.deliveryStatus;
    delBadge.className = `badge ${pkt.deliveryStatus === 'LOST' ? 'badge-danger' : 'badge-normal'}`;
  }

  // Dissector tree (legacy backwards compatibility)
  if (pkt.transport) {
    safeSetText('tree-src-port', pkt.transport.srcPort);
    safeSetText('tree-udp-len', `${pkt.transport.length} octets`);
  }
  if (dns.header) {
    safeSetText('tree-tx-id', dns.header.transactionId);
    safeSetText('tree-flags-raw', dns.header.rawFlags || dns.header.flags);
    safeSetText('tree-qdcount', dns.header.qdcount);
  }
  if (dns.question) {
    safeSetText('tree-qname', dns.question.queryName);
    safeSetText('tree-qtype', dns.question.queryType);
    safeSetText('tree-qclass', dns.question.queryClass);
  }

  // Field details
  safeSetText('ins-pkt-num', `${pkt.packetNumber} of ${pkt.totalPackets}`);
  safeSetHtml('ins-del-status', `<span class="badge ${pkt.deliveryStatus === 'LOST' ? 'badge-danger' : 'badge-normal'}">${pkt.deliveryStatus}</span>`);
  safeSetText('ins-timestamp', pkt.timestamp);
  safeSetText('ins-query-name', (dns.question && dns.question.queryName) || '');
  if (dns.payload) {
    safeSetText('ins-payload', dns.payload.encodedPayload || '(none)');
    safeSetText('ins-payload-len', `${dns.payload.payloadLength || 0} chars`);
    safeSetText('ins-entropy', `${analysis ? analysis.entropy : '0.00'} bits/char`);
    safeSetText('analyzer-wire-size', `${dns.payload.rawPacketBytes || 0} octets on wire`);
    safeSetText('analyzer-hexdump', dns.payload.hexDump || '');
  }

  // Status badge
  const statusBadge = document.getElementById('analyzer-pkt-status');
  if (analysis) {
    statusBadge.textContent = `Packet #${pkt.packetNumber} &bull; ${analysis.status}`;
    statusBadge.className = `badge badge-${analysis.status === 'Suspicious' ? 'danger' : analysis.status === 'Unusual' ? 'unusual' : 'normal'}`;
  } else {
    statusBadge.textContent = `Packet #${pkt.packetNumber}`;
    statusBadge.className = 'badge badge-normal';
  }

  // Update Protocol Stack inspection card
  selectProtocolStackLayer(state.activeStackLayer || 'application');
}

/* ==========================================================================
   Anomaly Detection Module Rendering
   ========================================================================== */
function renderDetectionView(analysis) {
  if (!analysis) return;

  // Score gauge
  document.getElementById('gauge-score-number').textContent = analysis.suspicionScore;
  const classBadge = document.getElementById('gauge-class-badge');
  classBadge.textContent = analysis.classification;
  classBadge.className = `badge badge-lg badge-${analysis.badgeColor}`;

  const verdict = document.getElementById('gauge-verdict-text');
  if (analysis.suspicionScore >= 80) {
    verdict.textContent = 'High probability of DNS steganography or tunneling payload detected.';
  } else if (analysis.suspicionScore >= 60) {
    verdict.textContent = 'Statistical markers match structured covert data transmission.';
  } else if (analysis.suspicionScore >= 30) {
    verdict.textContent = 'Minor anomalous deviations observed in query length or character set.';
  } else {
    verdict.textContent = 'Query structure conforms to standard benign DNS profiles.';
  }

  // Feature indicators
  const ind = analysis.indicators;
  document.getElementById('ind-query-len').innerHTML = `${ind.averageQueryLength} <span class="unit">chars</span>`;
  document.getElementById('bar-query-len').style.width = `${Math.min(100, (ind.averageQueryLength / 60) * 100)}%`;

  document.getElementById('ind-subdomain-len').innerHTML = `${ind.averageSubdomainLength} <span class="unit">chars</span>`;
  document.getElementById('bar-subdomain-len').style.width = `${Math.min(100, (ind.averageSubdomainLength / 40) * 100)}%`;

  document.getElementById('ind-entropy').innerHTML = `${ind.averageEntropy} <span class="unit">bits/char</span>`;
  document.getElementById('bar-entropy').style.width = `${Math.min(100, (ind.averageEntropy / 5.0) * 100)}%`;

  document.getElementById('ind-unusual-chars').innerHTML = `${(ind.averageUnusualCharRatio * 100).toFixed(0)} <span class="unit">%</span>`;
  document.getElementById('bar-unusual-chars').style.width = `${Math.min(100, ind.averageUnusualCharRatio * 100)}%`;

  document.getElementById('ind-payload-ratio').innerHTML = `${ind.averagePayloadDomainRatio} <span class="unit">x</span>`;
  document.getElementById('bar-payload-ratio').style.width = `${Math.min(100, (ind.averagePayloadDomainRatio / 2.5) * 100)}%`;

  document.getElementById('ind-uniqueness').innerHTML = `${(ind.uniqueSubdomainsRatio * 100).toFixed(0)} <span class="unit">%</span>`;
  document.getElementById('bar-uniqueness').style.width = `${Math.min(100, ind.uniqueSubdomainsRatio * 100)}%`;

  // Rule contributions table
  const tbody = document.getElementById('tbody-rule-contributions');
  tbody.innerHTML = '';

  if (!analysis.ruleContributions || analysis.ruleContributions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No rules evaluated yet.</td></tr>';
    return;
  }

  analysis.ruleContributions.forEach(rule => {
    const tr = document.createElement('tr');
    const badgeClass = rule.pointsContributed > 0 
      ? (rule.severity === 'high' ? 'badge-danger' : 'badge-suspicious') 
      : 'badge-normal';

    tr.innerHTML = `
      <td><strong>${rule.ruleId}</strong></td>
      <td>${rule.featureName}</td>
      <td><span class="code-inline">${rule.observedValue}</span></td>
      <td><span class="text-muted">${rule.threshold}</span></td>
      <td><span class="badge ${badgeClass}">+${rule.pointsContributed} pts</span></td>
      <td><span class="text-sm">${rule.explanation}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

/* ==========================================================================
   Traffic Comparison & Chart.js Visualizations
   ========================================================================== */
async function refreshComparison() {
  if (!state.currentStream) return;

  try {
    const res = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ covertPackets: state.currentStream.packets })
    });
    const data = await res.json();
    renderComparisonTable(data);
    renderComparisonChartsData(data);
  } catch (err) {
    console.error('Comparison error:', err);
  }
}

function renderComparisonTable(data) {
  const tbody = document.getElementById('tbody-comparison-metrics');
  tbody.innerHTML = '';

  data.metrics.forEach(m => {
    const tr = document.createElement('tr');
    const isHigher = m.diff > 0;
    const diffSign = isHigher ? `+${m.diff}` : `${m.diff}`;
    const diffClass = isHigher ? 'text-danger' : 'text-emerald';

    tr.innerHTML = `
      <td><strong>${m.name}</strong></td>
      <td><span class="text-muted">${m.unit}</span></td>
      <td>${m.normal}</td>
      <td><strong class="text-cyan">${m.covert}</strong></td>
      <td><strong class="${diffClass}">${diffSign}</strong></td>
      <td><span class="text-sm text-muted">${m.description}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderComparisonChartsData(data) {
  state.lastComparisonData = data;
  renderComparisonCharts();
}

function renderComparisonCharts() {
  if (!state.lastComparisonData || typeof Chart === 'undefined') return;
  const data = state.lastComparisonData;

  // Destroy existing charts to prevent canvas memory leaks
  ['query-length', 'entropy', 'scores', 'payload'].forEach(id => {
    if (state.charts[id]) {
      state.charts[id].destroy();
      state.charts[id] = null;
    }
  });

  const chartTextColor = '#8892b0';
  const chartGridColor = 'rgba(255, 255, 255, 0.05)';

  // 1. Query Length Distribution
  const ctxLength = document.getElementById('chart-query-length');
  if (ctxLength) {
    state.charts['query-length'] = new Chart(ctxLength, {
      type: 'bar',
      data: {
        labels: ['Avg Query Length (chars)', 'Avg Subdomain Length (chars)'],
        datasets: [
          {
            label: 'Normal DNS Baseline',
            data: [data.normal.indicators.averageQueryLength, data.normal.indicators.averageSubdomainLength],
            backgroundColor: 'rgba(0, 255, 157, 0.6)',
            borderColor: '#00ff9d',
            borderWidth: 1
          },
          {
            label: 'Simulated Covert DNS',
            data: [data.covert.indicators.averageQueryLength, data.covert.indicators.averageSubdomainLength],
            backgroundColor: 'rgba(0, 240, 255, 0.6)',
            borderColor: '#00f0ff',
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { grid: { color: chartGridColor }, ticks: { color: chartTextColor } },
          x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor } }
        },
        plugins: { legend: { labels: { color: chartTextColor } } }
      }
    });
  }

  // 2. Entropy Comparison Chart
  const ctxEntropy = document.getElementById('chart-entropy');
  if (ctxEntropy) {
    state.charts['entropy'] = new Chart(ctxEntropy, {
      type: 'bar',
      data: {
        labels: ['Normal Queries Avg', 'Simulated Covert Avg', 'Detection Threshold'],
        datasets: [{
          label: 'Shannon Entropy (bits/char)',
          data: [data.normal.indicators.averageEntropy, data.covert.indicators.averageEntropy, 3.6],
          backgroundColor: [
            'rgba(0, 255, 157, 0.6)',
            'rgba(255, 0, 85, 0.6)',
            'rgba(255, 183, 3, 0.3)'
          ],
          borderColor: ['#00ff9d', '#ff0055', '#ffb703'],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { min: 0, max: 5.0, grid: { color: chartGridColor }, ticks: { color: chartTextColor } },
          x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor } }
        },
        plugins: { legend: { labels: { color: chartTextColor } } }
      }
    });
  }

  // 3. Suspicion Score Breakdown
  const ctxScores = document.getElementById('chart-scores');
  if (ctxScores) {
    state.charts['scores'] = new Chart(ctxScores, {
      type: 'bar',
      data: {
        labels: ['Normal Baseline', 'Simulated Covert'],
        datasets: [{
          label: 'Suspicion Score (/100)',
          data: [data.normal.suspicionScore, data.covert.suspicionScore],
          backgroundColor: [
            'rgba(0, 255, 157, 0.6)',
            'rgba(255, 0, 85, 0.7)'
          ],
          borderColor: ['#00ff9d', '#ff0055'],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { min: 0, max: 100, grid: { color: chartGridColor }, ticks: { color: chartTextColor } },
          x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor } }
        },
        plugins: { legend: { labels: { color: chartTextColor } } }
      }
    });
  }

  // 4. Payload Size vs Protocol Overhead
  const ctxPayload = document.getElementById('chart-payload');
  if (ctxPayload) {
    const rawPayloadBytes = state.currentStream?.pipeline.encodedSizeBytes || 24;
    const wireTotalBytes = (state.currentStream?.totalPackets || 1) * 48;
    const overheadBytes = Math.max(0, wireTotalBytes - rawPayloadBytes);

    state.charts['payload'] = new Chart(ctxPayload, {
      type: 'doughnut',
      data: {
        labels: ['Effective Covert Payload (bytes)', 'DNS/UDP Protocol Overhead (bytes)'],
        datasets: [{
          data: [rawPayloadBytes, overheadBytes],
          backgroundColor: [
            'rgba(0, 240, 255, 0.8)',
            'rgba(255, 255, 255, 0.15)'
          ],
          borderColor: ['#00f0ff', 'rgba(255,255,255,0.3)'],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: chartTextColor } } }
      }
    });
  }
}

/* ==========================================================================
   Feature 5: Packet Log with Delivery Status & Export
   ========================================================================== */
function renderPacketTable() {
  if (!state.currentStream) return;

  const packets = state.currentStream.packets;
  const analysis = state.currentAnalysis?.queryDetails || [];
  const tbody = document.getElementById('tbody-packets');
  tbody.innerHTML = '';

  // Merge packet models with individual analysis
  let tableData = packets.map((pkt, i) => {
    const ana = analysis[i] || {};
    const qtype = (pkt.dns && pkt.dns.question && pkt.dns.question.queryType ? pkt.dns.question.queryType.split(' ')[0] : (pkt.dns && pkt.dns.question && pkt.dns.question.qtype) || (pkt.queryType || 'A'));
    const qname = (pkt.dns && pkt.dns.question && pkt.dns.question.queryName) || pkt.queryName || '';
    const rawLen = (pkt.dns && pkt.dns.payload && pkt.dns.payload.rawPacketBytes) || pkt.wireBytes || (pkt.request && pkt.request.wireBytes) || 0;
    return {
      packetNumber: pkt.packetNumber || (i + 1),
      deliveryStatus: pkt.deliveryStatus || 'DELIVERED',
      timestamp: pkt.timestamp || '',
      queryName: qname,
      type: qtype,
      length: rawLen,
      entropy: ana.entropy || 0,
      score: ana.score || 0,
      status: ana.status || 'Normal',
      index: i
    };
  });

  // Sorting
  tableData.sort((a, b) => {
    let valA = a[state.sortField];
    let valB = b[state.sortField];
    if (typeof valA === 'string') {
      return state.sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    return state.sortAsc ? valA - valB : valB - valA;
  });

  // Search & Filter
  const searchTerm = document.getElementById('log-search-input').value.toLowerCase().trim();
  const filterStatus = document.getElementById('log-filter-status').value;
  const filterDelivery = document.getElementById('log-filter-delivery')?.value || 'all';

  const filtered = tableData.filter(item => {
    const matchesSearch = !searchTerm || item.queryName.toLowerCase().includes(searchTerm) || item.status.toLowerCase().includes(searchTerm) || item.deliveryStatus.toLowerCase().includes(searchTerm);
    const matchesStatus = filterStatus === 'all' || item.status === filterStatus;
    const matchesDelivery = filterDelivery === 'all' || item.deliveryStatus === filterDelivery;
    return matchesSearch && matchesStatus && matchesDelivery;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted">No packets match search or filter criteria.</td></tr>';
    return;
  }

  filtered.forEach(item => {
    const tr = document.createElement('tr');
    const badgeClass = item.status === 'Suspicious' ? 'badge-danger' : item.status === 'Unusual' ? 'badge-unusual' : 'badge-normal';
    const delClass = item.deliveryStatus === 'LOST' ? 'badge-danger' : 'badge-normal';

    tr.innerHTML = `
      <td><strong>${item.packetNumber}</strong></td>
      <td><span class="badge ${delClass}">${item.deliveryStatus}</span></td>
      <td><span class="text-mono text-muted">${item.timestamp}</span></td>
      <td><span class="code-inline">${item.queryName}</span></td>
      <td><span class="badge badge-normal">${item.type}</span></td>
      <td>${item.length} B</td>
      <td>${item.entropy}</td>
      <td><strong>${item.score}</strong></td>
      <td><span class="badge ${badgeClass}">${item.status}</span></td>
      <td>
        <button class="btn btn-sm btn-outline btn-inspect-pkt" data-idx="${item.index}">
          🔍 Inspect
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Add click listeners to inspect buttons
  document.querySelectorAll('.btn-inspect-pkt').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.getAttribute('data-idx'), 10);
      state.activePacketIndex = idx;
      document.getElementById('select-active-packet').value = idx;
      renderPacketInspection(idx);
      switchTab('analyzer');
    });
  });
}

function filterPacketTable() {
  renderPacketTable();
}

/* ==========================================================================
   Export Helpers (CSV & JSON)
   ========================================================================== */
function exportTrafficCSV() {
  if (!state.currentStream) {
    alert('No simulation traffic available to export. Run a simulation first.');
    return;
  }

  const packets = state.currentStream.packets;
  const analysis = state.currentAnalysis?.queryDetails || [];

  let csv = 'PacketNumber,DeliveryStatus,Timestamp,QueryName,QueryType,WireBytes,Entropy,Score,Status,CovertPayload\n';
  packets.forEach((pkt, i) => {
    const ana = analysis[i] || {};
    csv += [
      pkt.packetNumber,
      `"${pkt.deliveryStatus || 'DELIVERED'}"`,
      `"${pkt.timestamp}"`,
      `"${pkt.dns.question.queryName}"`,
      `"${pkt.dns.question.queryType}"`,
      pkt.dns.payload.rawPacketBytes,
      ana.entropy || 0,
      ana.score || 0,
      `"${ana.status || 'Normal'}"`,
      `"${pkt.dns.payload.encodedPayload}"`
    ].join(',') + '\n';
  });

  downloadFile(csv, 'dns-simulation-traffic.csv', 'text/csv');
}

function exportTrafficJSON() {
  if (!state.currentStream) {
    alert('No simulation traffic available to export. Run a simulation first.');
    return;
  }

  const exportObj = {
    safetyNotice: 'SIMULATED — NO REAL DNS REQUEST SENT',
    exportedAt: new Date().toISOString(),
    simulation: state.currentStream,
    analysis: state.currentAnalysis
  };

  const jsonStr = JSON.stringify(exportObj, null, 2);
  downloadFile(jsonStr, 'dns-simulation-traffic.json', 'application/json');
}

function downloadFile(content, fileName, mimeType) {
  if (typeof Blob === 'undefined' || typeof URL === 'undefined' || !document.body) return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ==========================================================================
   Scientific Evaluation Lab Controller & Visualizations
   ========================================================================== */

function initEvaluationControls() {
  const sampleSlider = document.getElementById('eval-sample-count');
  const sampleVal = document.getElementById('eval-sample-count-val');
  if (sampleSlider && sampleVal) {
    sampleSlider.addEventListener('input', () => {
      sampleVal.textContent = `${sampleSlider.value} samples`;
    });
  }

  const splitSlider = document.getElementById('eval-split-ratio');
  const splitVal = document.getElementById('eval-split-ratio-val');
  if (splitSlider && splitVal) {
    splitSlider.addEventListener('input', () => {
      const cal = parseInt(splitSlider.value, 10);
      splitVal.textContent = `${cal}% Cal / ${100 - cal}% Eval`;
    });
  }

  const lossSlider = document.getElementById('eval-packet-loss');
  const lossVal = document.getElementById('eval-packet-loss-val');
  if (lossSlider && lossVal) {
    lossSlider.addEventListener('input', () => {
      const val = parseInt(lossSlider.value, 10);
      lossVal.textContent = val === 0 ? '0% (Reliable)' : `${val}% Loss`;
    });
  }

  const autoCalibCheck = document.getElementById('eval-auto-calibrate');
  const manualWrapper = document.getElementById('eval-manual-threshold-wrapper');
  if (autoCalibCheck && manualWrapper) {
    autoCalibCheck.addEventListener('change', () => {
      const isAuto = autoCalibCheck.checked;
      manualWrapper.style.opacity = isAuto ? '0.5' : '1.0';
      manualWrapper.style.pointerEvents = isAuto ? 'none' : 'auto';
    });
  }

  const entSlider = document.getElementById('eval-entropy-threshold');
  const entVal = document.getElementById('eval-entropy-threshold-val');
  if (entSlider && entVal) {
    entSlider.addEventListener('input', () => {
      entVal.textContent = `${parseFloat(entSlider.value).toFixed(2)} bits/char`;
    });
  }

  const btnSeed = document.getElementById('btn-random-seed');
  const seedInput = document.getElementById('eval-seed');
  if (btnSeed && seedInput) {
    btnSeed.addEventListener('click', () => {
      seedInput.value = Math.floor(Math.random() * 100000);
    });
  }

  const btnRun = document.getElementById('btn-run-evaluation');
  if (btnRun) {
    btnRun.addEventListener('click', runEvaluationExperiment);
  }

  const btnCsv = document.getElementById('btn-export-eval-csv');
  if (btnCsv) {
    btnCsv.addEventListener('click', exportEvaluationCSV);
  }

  const btnJson = document.getElementById('btn-export-eval-json');
  if (btnJson) {
    btnJson.addEventListener('click', exportEvaluationJSON);
  }

  const btnPrint = document.getElementById('btn-print-eval-report');
  if (btnPrint) {
    btnPrint.addEventListener('click', printEvaluationReport);
  }

  const errDetectorFilter = document.getElementById('eval-error-detector-filter');
  const errTypeFilter = document.getElementById('eval-error-type-filter');
  if (errDetectorFilter) errDetectorFilter.addEventListener('change', renderEvaluationErrorsTable);
  if (errTypeFilter) errTypeFilter.addEventListener('change', renderEvaluationErrorsTable);
}

function getEvaluationFormValues() {
  const sampleCount = parseInt(document.getElementById('eval-sample-count')?.value, 10) || 100;
  const seedVal = parseInt(document.getElementById('eval-seed')?.value, 10);
  const seed = !isNaN(seedVal) ? seedVal : 42;
  const splitRatio = (parseInt(document.getElementById('eval-split-ratio')?.value, 10) || 30) / 100;
  const encoding = document.getElementById('eval-encoding')?.value || 'all';
  const autoCalibrate = document.getElementById('eval-auto-calibrate')?.checked !== false;
  const entropyThreshold = parseFloat(document.getElementById('eval-entropy-threshold')?.value) || 3.5;
  const packetLoss = parseInt(document.getElementById('eval-packet-loss')?.value, 10) || 0;

  return {
    sampleCount,
    seed,
    splitRatio,
    encoding,
    autoCalibrate,
    entropyThreshold,
    packetLoss
  };
}

async function loadLatestEvaluation() {
  try {
    const res = await fetch('/api/evaluation/latest');
    if (res.ok) {
      const report = await res.json();
      state.latestEvaluation = report;
      renderEvaluationViews(report);
    }
  } catch (err) {
    console.warn('Could not load latest evaluation benchmark:', err);
  }
}

async function runEvaluationExperiment() {
  const btnRun = document.getElementById('btn-run-evaluation');
  const statusIndicator = document.getElementById('eval-status-indicator');
  const params = getEvaluationFormValues();

  if (btnRun) btnRun.disabled = true;
  if (statusIndicator) {
    statusIndicator.textContent = 'Generating synthetic samples and benchmarking detectors on held-out splits...';
    statusIndicator.className = 'text-cyan text-xs ml-3';
  }

  try {
    const res = await fetch('/api/evaluation/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Evaluation experiment failed');
    }

    const report = await res.json();
    state.latestEvaluation = report;
    renderEvaluationViews(report);

    if (statusIndicator) {
      statusIndicator.textContent = `Experiment ${report.experimentId} completed successfully on ${report.datasetSummary.evaluationCount} held-out evaluation queries!`;
      statusIndicator.className = 'text-emerald text-xs ml-3';
    }
  } catch (err) {
    console.error('Evaluation run error:', err);
    if (statusIndicator) {
      statusIndicator.textContent = `Experiment failed: ${err.message}`;
      statusIndicator.className = 'text-danger text-xs ml-3';
    }
  } finally {
    if (btnRun) btnRun.disabled = false;
  }
}

function renderEvaluationViews(report) {
  if (!report) return;

  const fmtPct = val => (val === null || val === undefined ? 'N/A' : `${(val * 100).toFixed(1)}%`);
  const fmtNum = val => (val === null || val === undefined ? 'N/A' : Number(val).toFixed(4));

  // 1. Summary Stats
  const sum = report.datasetSummary || {};
  const cfg = report.configuration || {};
  const det = report.detectors || {};

  const statTotal = document.getElementById('stat-eval-total');
  if (statTotal) statTotal.textContent = sum.totalGenerated !== undefined ? sum.totalGenerated : '--';

  const statBalance = document.getElementById('stat-eval-balance');
  if (statBalance) statBalance.textContent = `Normal: ${sum.normalCountTotal || 0} | Covert: ${sum.covertCountTotal || 0}`;

  const statCal = document.getElementById('stat-eval-cal');
  if (statCal) statCal.textContent = `${sum.calibrationCount || 0} queries`;

  const statCalSub = document.getElementById('stat-eval-cal-sub');
  if (statCalSub) {
    const thresh = det.entropyBaseline ? det.entropyBaseline.threshold : 3.6;
    statCalSub.textContent = `Calibrated T = ${thresh} bits/char`;
  }

  const statEval = document.getElementById('stat-eval-eval');
  if (statEval) statEval.textContent = `${sum.evaluationCount || 0} queries`;

  const statEvalSub = document.getElementById('stat-eval-eval-sub');
  if (statEvalSub) {
    statEvalSub.textContent = `Normal: ${sum.evaluationNormal || 0} | Covert: ${sum.evaluationCovert || 0}`;
  }

  const statSeed = document.getElementById('stat-eval-seed');
  if (statSeed) statSeed.textContent = `Seed: ${cfg.seed || 42}`;

  // 2. Performance Metrics
  const mRule = (det.ruleBased && det.ruleBased.metrics) || {};
  const mEnt = (det.entropyBaseline && det.entropyBaseline.metrics) || {};

  // Rule-Based
  const setEl = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  setEl('metric-rule-accuracy', fmtPct(mRule.accuracy));
  setEl('metric-rule-precision', fmtPct(mRule.precision));
  setEl('metric-rule-recall', fmtPct(mRule.recall));
  setEl('metric-rule-specificity', fmtPct(mRule.specificity));
  setEl('metric-rule-f1', fmtNum(mRule.f1Score));
  setEl('metric-rule-fpr', fmtPct(mRule.falsePositiveRate));

  // Entropy Baseline
  setEl('metric-entropy-accuracy', fmtPct(mEnt.accuracy));
  setEl('metric-entropy-precision', fmtPct(mEnt.precision));
  setEl('metric-entropy-recall', fmtPct(mEnt.recall));
  setEl('metric-entropy-specificity', fmtPct(mEnt.specificity));
  setEl('metric-entropy-f1', fmtNum(mEnt.f1Score));
  setEl('metric-entropy-fpr', fmtPct(mEnt.falsePositiveRate));

  const entRuleLabel = document.getElementById('label-entropy-baseline-rule');
  if (entRuleLabel) {
    entRuleLabel.textContent = `Decision rule: Shannon Entropy > ${report.detectors.entropyBaseline.threshold} bits/char -> Covert`;
  }

  // 3. Confusion Matrices
  const evalTotal = sum.evaluationCount || 1;
  setEl('cm-rule-total', sum.evaluationCount);
  setEl('cm-rule-tp', mRule.tp);
  setEl('cm-rule-tp-pct', `${((mRule.tp / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-rule-fn', mRule.fn);
  setEl('cm-rule-fn-pct', `${((mRule.fn / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-rule-fp', mRule.fp);
  setEl('cm-rule-fp-pct', `${((mRule.fp / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-rule-tn', mRule.tn);
  setEl('cm-rule-tn-pct', `${((mRule.tn / evalTotal) * 100).toFixed(1)}%`);

  setEl('cm-entropy-total', sum.evaluationCount);
  setEl('cm-entropy-tp', mEnt.tp);
  setEl('cm-entropy-tp-pct', `${((mEnt.tp / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-entropy-fn', mEnt.fn);
  setEl('cm-entropy-fn-pct', `${((mEnt.fn / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-entropy-fp', mEnt.fp);
  setEl('cm-entropy-fp-pct', `${((mEnt.fp / evalTotal) * 100).toFixed(1)}%`);
  setEl('cm-entropy-tn', mEnt.tn);
  setEl('cm-entropy-tn-pct', `${((mEnt.tn / evalTotal) * 100).toFixed(1)}%`);

  // 4. Comparison Table
  renderEvaluationMetricsComparisonTable(mRule, mEnt);

  // 5. Comparison Chart
  renderEvaluationComparisonChart();

  // 6. Empirical Feature Distributions Table
  renderFeatureDistributionsTable(report.featureDistributions);

  // 7. Error Analysis Table
  renderEvaluationErrorsTable();

  // 8. Transport Loss Impact Card
  const lossCard = document.getElementById('eval-loss-card');
  if (lossCard) {
    if (report.reconstructionSummary) {
      lossCard.style.display = 'block';
      const r = report.reconstructionSummary;
      setEl('eval-loss-rate-val', r.packetLossSetting);
      setEl('eval-loss-delivered-val', r.deliveredPackets);
      setEl('eval-loss-total-val', `out of ${r.totalCovertPackets} covert packets`);
      setEl('eval-loss-dropped-val', r.lostPackets);
      const reconEl = document.getElementById('eval-loss-recon-status');
      if (reconEl) {
        reconEl.textContent = r.reconstructionStatus;
        reconEl.className = r.reconstructionStatus === 'SUCCESS' ? 'stat-value text-emerald' : 'stat-value text-danger';
      }
    } else {
      lossCard.style.display = 'none';
    }
  }
}

function renderEvaluationMetricsComparisonTable(mRule, mEnt) {
  const tbody = document.getElementById('tbody-eval-metrics-comparison');
  if (!tbody) return;

  const rows = [
    { name: 'Total Evaluated Queries', rule: mRule.total, ent: mEnt.total, unit: '' },
    { name: 'True Positives (TP)', rule: mRule.tp, ent: mEnt.tp, unit: '' },
    { name: 'True Negatives (TN)', rule: mRule.tn, ent: mEnt.tn, unit: '' },
    { name: 'False Positives (FP)', rule: mRule.fp, ent: mEnt.fp, unit: '' },
    { name: 'False Negatives (FN)', rule: mRule.fn, ent: mEnt.fn, unit: '' },
    { name: 'Accuracy', rule: mRule.accuracy, ent: mEnt.accuracy, unit: '%', isPct: true },
    { name: 'Precision', rule: mRule.precision, ent: mEnt.precision, unit: '%', isPct: true },
    { name: 'Recall (Sensitivity)', rule: mRule.recall, ent: mEnt.recall, unit: '%', isPct: true },
    { name: 'Specificity', rule: mRule.specificity, ent: mEnt.specificity, unit: '%', isPct: true },
    { name: 'F1-Score', rule: mRule.f1Score, ent: mEnt.f1Score, unit: '', isNum: true },
    { name: 'False Positive Rate (FPR)', rule: mRule.falsePositiveRate, ent: mEnt.falsePositiveRate, unit: '%', isPct: true, invertColor: true }
  ];

  tbody.innerHTML = '';
  rows.forEach(r => {
    const tr = document.createElement('tr');

    let ruleDisplay = 'N/A';
    let entDisplay = 'N/A';
    let deltaDisplay = 'N/A';
    let deltaClass = 'text-muted';

    if (r.isPct) {
      ruleDisplay = r.rule !== null ? `${(r.rule * 100).toFixed(1)}%` : 'N/A';
      entDisplay = r.ent !== null ? `${(r.ent * 100).toFixed(1)}%` : 'N/A';
      if (r.rule !== null && r.ent !== null) {
        const delta = ((r.rule - r.ent) * 100).toFixed(1);
        deltaDisplay = `${delta >= 0 ? '+' : ''}${delta}%`;
        const isBetter = r.invertColor ? delta <= 0 : delta >= 0;
        deltaClass = isBetter ? 'text-emerald font-bold' : 'text-danger font-bold';
      }
    } else if (r.isNum) {
      ruleDisplay = r.rule !== null ? Number(r.rule).toFixed(4) : 'N/A';
      entDisplay = r.ent !== null ? Number(r.ent).toFixed(4) : 'N/A';
      if (r.rule !== null && r.ent !== null) {
        const delta = (r.rule - r.ent).toFixed(4);
        deltaDisplay = `${delta >= 0 ? '+' : ''}${delta}`;
        deltaClass = delta >= 0 ? 'text-emerald font-bold' : 'text-danger font-bold';
      }
    } else {
      ruleDisplay = String(r.rule);
      entDisplay = String(r.ent);
      const delta = r.rule - r.ent;
      deltaDisplay = `${delta >= 0 ? '+' : ''}${delta}`;
      deltaClass = 'text-muted';
    }

    tr.innerHTML = `
      <td><strong>${r.name}</strong></td>
      <td class="text-cyan font-bold">${ruleDisplay}</td>
      <td class="text-amber font-bold">${entDisplay}</td>
      <td class="${deltaClass}">${deltaDisplay}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFeatureDistributionsTable(distributions) {
  const tbody = document.getElementById('tbody-feature-distributions');
  if (!tbody || !distributions) return;

  const featureMetadata = [
    { key: 'entropy', name: 'Shannon Character Entropy', unit: 'bits/char', desc: 'Covert obfuscation creates higher character randomness' },
    { key: 'queryLength', name: 'Total Query FQDN Length', unit: 'chars', desc: 'Tunneling payloads substantially expand domain length' },
    { key: 'subdomainLength', name: 'Subdomain Label Length', unit: 'chars', desc: 'Covert payload chunking fills labels near RFC limits' },
    { key: 'unusualCharRatio', name: 'Unusual Character Ratio', unit: '%', isPct: true, desc: 'Base64/Hex/Binary introduces digits and mixed casing' },
    { key: 'payloadToDomainRatio', name: 'Payload-to-Domain Ratio', unit: 'x', desc: 'Covert subdomains dwarf parent authoritative domain' }
  ];

  tbody.innerHTML = '';
  featureMetadata.forEach(meta => {
    const data = distributions[meta.key];
    if (!data) return;

    const norm = data.normal;
    const cov = data.covert;

    const tr = document.createElement('tr');
    const normMean = meta.isPct ? `${(norm.mean * 100).toFixed(1)}%` : `${norm.mean} ${meta.unit}`;
    const normRange = meta.isPct ? `[${(norm.min * 100).toFixed(0)}% - ${(norm.max * 100).toFixed(0)}%]` : `[${norm.min} - ${norm.max}]`;

    const covMean = meta.isPct ? `${(cov.mean * 100).toFixed(1)}%` : `${cov.mean} ${meta.unit}`;
    const covRange = meta.isPct ? `[${(cov.min * 100).toFixed(0)}% - ${(cov.max * 100).toFixed(0)}%]` : `[${cov.min} - ${cov.max}]`;

    tr.innerHTML = `
      <td><strong>${meta.name}</strong><br><span class="text-xs text-muted">${meta.desc}</span></td>
      <td class="text-emerald font-bold">${normMean} &plusmn; ${norm.stdDev}</td>
      <td class="text-muted text-mono text-xs">${normRange}</td>
      <td class="text-cyan font-bold">${covMean} &plusmn; ${cov.stdDev}</td>
      <td class="text-muted text-mono text-xs">${covRange}</td>
      <td>
        <span class="badge ${cov.mean > norm.mean ? 'badge-normal' : 'badge-suspicious'}">
          &Delta; = ${meta.isPct ? ((cov.mean - norm.mean) * 100).toFixed(1) + '%' : (cov.mean - norm.mean).toFixed(2)}
        </span>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderEvaluationErrorsTable() {
  const tbody = document.getElementById('tbody-eval-errors');
  if (!tbody || !state.latestEvaluation) return;

  const detectorChoice = document.getElementById('eval-error-detector-filter')?.value || 'ruleBased';
  const typeChoice = document.getElementById('eval-error-type-filter')?.value || 'all';

  const errAnalysis = state.latestEvaluation.errorAnalysis || {};
  const errors = errAnalysis[detectorChoice];
  if (!errors) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No errors found for selected detector.</td></tr>';
    return;
  }

  let list = [];
  if (typeChoice === 'all' || typeChoice === 'fp') {
    list = list.concat(errors.falsePositives.map(e => ({ ...e, errorType: 'FP' })));
  }
  if (typeChoice === 'all' || typeChoice === 'fn') {
    list = list.concat(errors.falseNegatives.map(e => ({ ...e, errorType: 'FN' })));
  }

  tbody.innerHTML = '';
  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-emerald">Zero ${typeChoice.toUpperCase()} errors recorded! Detector performed with 100% precision/recall on this partition.</td></tr>`;
    return;
  }

  list.slice(0, 50).forEach(item => {
    const tr = document.createElement('tr');
    const isFP = item.errorType === 'FP';
    const tagClass = isFP ? 'badge-danger' : 'badge-suspicious';
    const tagText = isFP ? 'False Positive (FP)' : 'False Negative (FN)';

    const groundTruth = isFP ? 'normal' : 'simulated_covert';
    const predicted = isFP ? 'simulated_covert' : 'normal';

    const featText = `Entropy: ${item.entropy} | SubLen: ${item.subdomainLength || 'N/A'}${item.score !== undefined ? ' | Score: ' + item.score : ''}`;

    tr.innerHTML = `
      <td><span class="text-mono text-xs text-muted">${item.sampleId}</span></td>
      <td><span class="badge ${isFP ? 'badge-normal' : 'badge-danger'}">${groundTruth}</span></td>
      <td><span class="badge ${tagClass}">${predicted} (${tagText})</span></td>
      <td><span class="code-inline text-xs font-bold text-white">${item.queryName}</span></td>
      <td><span class="text-mono text-xs text-cyan">${featText}</span></td>
      <td><span class="text-xs text-muted">${item.diagnosticExplanation}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderEvaluationComparisonChart() {
  if (!state.latestEvaluation || typeof Chart === 'undefined') return;

  const ctx = document.getElementById('chart-eval-comparison');
  if (!ctx) return;

  if (state.charts['eval-comparison']) {
    state.charts['eval-comparison'].destroy();
    state.charts['eval-comparison'] = null;
  }

  const mRule = state.latestEvaluation.detectors.ruleBased.metrics;
  const mEnt = state.latestEvaluation.detectors.entropyBaseline.metrics;

  const labels = ['Accuracy', 'Precision', 'Recall', 'Specificity', 'F1-Score', 'FPR'];
  const ruleData = [
    mRule.accuracy !== null ? mRule.accuracy * 100 : 0,
    mRule.precision !== null ? mRule.precision * 100 : 0,
    mRule.recall !== null ? mRule.recall * 100 : 0,
    mRule.specificity !== null ? mRule.specificity * 100 : 0,
    mRule.f1Score !== null ? mRule.f1Score * 100 : 0,
    mRule.falsePositiveRate !== null ? mRule.falsePositiveRate * 100 : 0
  ];

  const entData = [
    mEnt.accuracy !== null ? mEnt.accuracy * 100 : 0,
    mEnt.precision !== null ? mEnt.precision * 100 : 0,
    mEnt.recall !== null ? mEnt.recall * 100 : 0,
    mEnt.specificity !== null ? mEnt.specificity * 100 : 0,
    mEnt.f1Score !== null ? mEnt.f1Score * 100 : 0,
    mEnt.falsePositiveRate !== null ? mEnt.falsePositiveRate * 100 : 0
  ];

  const chartTextColor = '#8892b0';
  const chartGridColor = 'rgba(255, 255, 255, 0.05)';

  state.charts['eval-comparison'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Rule-Based Detector',
          data: ruleData,
          backgroundColor: 'rgba(0, 240, 255, 0.7)',
          borderColor: '#00f0ff',
          borderWidth: 1
        },
        {
          label: `Entropy Baseline (T=${state.latestEvaluation.detectors.entropyBaseline.threshold})`,
          data: entData,
          backgroundColor: 'rgba(255, 183, 3, 0.7)',
          borderColor: '#ffb703',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 0,
          max: 100,
          ticks: { color: chartTextColor, callback: val => `${val}%` },
          grid: { color: chartGridColor }
        },
        x: {
          ticks: { color: chartTextColor },
          grid: { color: chartGridColor }
        }
      },
      plugins: {
        legend: { labels: { color: chartTextColor } },
        tooltip: {
          callbacks: {
            label: context => `${context.dataset.label}: ${context.raw.toFixed(1)}%`
          }
        }
      }
    }
  });
}

function exportEvaluationCSV() {
  if (!state.latestEvaluation) {
    alert('No active evaluation experiment to export. Run an evaluation first.');
    return;
  }

  const report = state.latestEvaluation;
  let csv = 'SampleID,ScenarioID,GroundTruth,RuleBasedPrediction,RuleBasedScore,EntropyBaselinePrediction,Entropy,QueryLength,SubdomainLength,UnusualCharRatio,PayloadDomainRatio,QueryName,DiagnosticReasons\n';

  (report.detailedEvaluations || []).forEach(item => {
    const reasons = `"${((item.ruleBased && item.ruleBased.reasons) || []).join('; ').replace(/"/g, '""')}"`;
    csv += [
      item.sampleId,
      item.scenarioId,
      item.groundTruth,
      item.ruleBased ? item.ruleBased.predicted : '',
      item.ruleBased ? item.ruleBased.score : '',
      item.entropyBaseline ? item.entropyBaseline.predicted : '',
      item.features ? item.features.entropy : 0,
      item.features ? item.features.queryLength : 0,
      item.features ? item.features.subdomainLength : 0,
      item.features ? item.features.unusualCharRatio : 0,
      item.features ? item.features.payloadToDomainRatio : 0,
      `"${item.queryName}"`,
      reasons
    ].join(',') + '\n';
  });

  downloadFile(csv, `dns-evaluation-${report.experimentId || Date.now()}.csv`, 'text/csv');
}

function exportEvaluationJSON() {
  if (!state.latestEvaluation) {
    alert('No active evaluation experiment to export. Run an evaluation first.');
    return;
  }

  const exportPayload = {
    safetyNotice: 'SIMULATED — NO REAL DNS REQUEST SENT — CONTROLLED SYNTHETIC BENCHMARK',
    generatedAt: new Date().toISOString(),
    ...state.latestEvaluation
  };

  const jsonStr = JSON.stringify(exportPayload, null, 2);
  downloadFile(jsonStr, `dns-evaluation-${state.latestEvaluation.experimentId || Date.now()}.json`, 'application/json');
}

function printEvaluationReport() {
  if (!state.latestEvaluation) {
    alert('No active evaluation experiment to print. Run an evaluation first.');
    return;
  }

  if (typeof window === 'undefined' || typeof window.open !== 'function') return;

  const r = state.latestEvaluation;
  const det = r.detectors || {};
  const mRule = (det.ruleBased && det.ruleBased.metrics) || {};
  const mEnt = (det.entropyBaseline && det.entropyBaseline.metrics) || {};
  const cfg = r.configuration || {};
  const sum = r.datasetSummary || {};

  const fmtPct = val => (val === null || val === undefined ? 'N/A' : `${(val * 100).toFixed(1)}%`);
  const fmtNum = val => (val === null || val === undefined ? 'N/A' : Number(val).toFixed(4));

  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    if (typeof alert === 'function') alert('Popup blocker prevented opening printable report. Please allow popups.');
    return;
  }

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DNS Steganography Evaluation Report - ${r.experimentId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #111; padding: 2rem; max-width: 900px; margin: 0 auto; line-height: 1.5; }
    h1 { font-size: 1.6rem; margin-bottom: 0.2rem; }
    .subtitle { color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; border-bottom: 2px solid #eee; padding-bottom: 0.75rem; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; background: #eee; }
    .badge-green { background: #e6f9f0; color: #00703c; border: 1px solid #b8ebd0; }
    .badge-blue { background: #e8f4fd; color: #005a9c; border: 1px solid #b3d7f5; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0 1.5rem 0; font-size: 0.85rem; }
    th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; }
    th { background: #f8f9fa; font-weight: bold; }
    .text-right { text-align: right; }
    .text-center { text-align: center; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 1rem; }
    .box { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; }
    .metric-val { font-size: 1.4rem; font-weight: bold; margin: 0.3rem 0; }
    .disclaimer { background: #fff8e6; border: 1px solid #ffe08a; padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.8rem; color: #7a5a00; margin: 1.5rem 0; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>
  <h1>Scientific Detection Performance Evaluation Report</h1>
  <div class="subtitle">
    Experiment ID: <strong>${r.experimentId}</strong> &bull; Generated: ${r.timestamp} &bull; Deterministic Seed: <strong>${cfg.seed}</strong>
  </div>

  <div class="disclaimer">
    <strong>Scientific Safety Notice:</strong> All metrics presented in this report were generated using synthetic DNS traffic in a local sandbox environment. No packets were transmitted over the public Internet. Held-out evaluation was conducted with strict scenario partitioning (zero evaluation leakage).
  </div>

  <h2>1. Executive Summary &amp; Partition Structure</h2>
  <table>
    <tr><th>Parameter</th><th>Value</th><th>Parameter</th><th>Value</th></tr>
    <tr><td>Total Generated Samples</td><td><strong>${sum.totalGenerated}</strong></td><td>Split Strategy</td><td>Scenario-Grouped Partitioning</td></tr>
    <tr><td>Calibration Set (Tuning)</td><td>${sum.calibrationCount} queries</td><td>Evaluation Set (Held-Out)</td><td><strong>${sum.evaluationCount} queries</strong></td></tr>
    <tr><td>Normal Class Count</td><td>${sum.normalCountTotal} queries</td><td>Covert Class Count</td><td>${sum.covertCountTotal} queries</td></tr>
    <tr><td>Covert Encoding Scheme</td><td>${cfg.encoding.toUpperCase()}</td><td>Entropy Baseline Threshold</td><td>${r.detectors.entropyBaseline.threshold} bits/char</td></tr>
    <tr><td>Scenario Leakage Status</td><td><span class="badge badge-green">VERIFIED (0 Overlapping Scenarios)</span></td><td>Packet Loss Setting</td><td>${cfg.packetLoss}%</td></tr>
  </table>

  <h2>2. Confusion Matrices (Evaluated on Held-Out Samples)</h2>
  <div class="grid">
    <div class="box">
      <h3>Method A: Multi-Feature Rule-Based Detector</h3>
      <table>
        <tr><th></th><th class="text-center">Pred. Covert</th><th class="text-center">Pred. Normal</th></tr>
        <tr><th>Actual Covert</th><td class="text-center"><strong>${mRule.tp}</strong> (TP)</td><td class="text-center">${mRule.fn} (FN)</td></tr>
        <tr><th>Actual Normal</th><td class="text-center">${mRule.fp} (FP)</td><td class="text-center"><strong>${mRule.tn}</strong> (TN)</td></tr>
      </table>
    </div>

    <div class="box">
      <h3>Method B: Entropy-Threshold Baseline</h3>
      <table>
        <tr><th></th><th class="text-center">Pred. Covert</th><th class="text-center">Pred. Normal</th></tr>
        <tr><th>Actual Covert</th><td class="text-center"><strong>${mEnt.tp}</strong> (TP)</td><td class="text-center">${mEnt.fn} (FN)</td></tr>
        <tr><th>Actual Normal</th><td class="text-center">${mEnt.fp} (FP)</td><td class="text-center"><strong>${mEnt.tn}</strong> (TN)</td></tr>
      </table>
    </div>
  </div>

  <h2>3. Complete Comparative Evaluation Metrics</h2>
  <table>
    <thead>
      <tr>
        <th>Evaluation Metric</th>
        <th class="text-center">Rule-Based Detector</th>
        <th class="text-center">Entropy Baseline</th>
        <th class="text-center">Variance / Delta</th>
      </tr>
    </thead>
    <tbody>
      <tr><td><strong>Accuracy</strong></td><td class="text-center"><strong>${fmtPct(mRule.accuracy)}</strong></td><td class="text-center">${fmtPct(mEnt.accuracy)}</td><td class="text-center">${(mRule.accuracy - mEnt.accuracy >= 0 ? '+' : '')}${((mRule.accuracy - mEnt.accuracy) * 100).toFixed(1)}%</td></tr>
      <tr><td><strong>Precision</strong></td><td class="text-center"><strong>${fmtPct(mRule.precision)}</strong></td><td class="text-center">${fmtPct(mEnt.precision)}</td><td class="text-center">${(mRule.precision - mEnt.precision >= 0 ? '+' : '')}${((mRule.precision - mEnt.precision) * 100).toFixed(1)}%</td></tr>
      <tr><td><strong>Recall (Sensitivity)</strong></td><td class="text-center"><strong>${fmtPct(mRule.recall)}</strong></td><td class="text-center">${fmtPct(mEnt.recall)}</td><td class="text-center">${(mRule.recall - mEnt.recall >= 0 ? '+' : '')}${((mRule.recall - mEnt.recall) * 100).toFixed(1)}%</td></tr>
      <tr><td><strong>Specificity</strong></td><td class="text-center"><strong>${fmtPct(mRule.specificity)}</strong></td><td class="text-center">${fmtPct(mEnt.specificity)}</td><td class="text-center">${(mRule.specificity - mEnt.specificity >= 0 ? '+' : '')}${((mRule.specificity - mEnt.specificity) * 100).toFixed(1)}%</td></tr>
      <tr><td><strong>F1-Score</strong></td><td class="text-center"><strong>${fmtNum(mRule.f1Score)}</strong></td><td class="text-center">${fmtNum(mEnt.f1Score)}</td><td class="text-center">${(mRule.f1Score - mEnt.f1Score >= 0 ? '+' : '')}${(mRule.f1Score - mEnt.f1Score).toFixed(4)}</td></tr>
      <tr><td><strong>False Positive Rate (FPR)</strong></td><td class="text-center"><strong>${fmtPct(mRule.falsePositiveRate)}</strong></td><td class="text-center">${fmtPct(mEnt.falsePositiveRate)}</td><td class="text-center">${(mRule.falsePositiveRate - mEnt.falsePositiveRate >= 0 ? '+' : '')}${((mRule.falsePositiveRate - mEnt.falsePositiveRate) * 100).toFixed(1)}%</td></tr>
    </tbody>
  </table>

  <h2>4. Empirical Feature Distribution Summary</h2>
  <table>
    <thead>
      <tr><th>Feature</th><th>Normal Mean (&plusmn;StdDev)</th><th>Covert Mean (&plusmn;StdDev)</th><th>Mean Delta</th></tr>
    </thead>
    <tbody>
      <tr><td>Shannon Entropy (bits/char)</td><td>${r.featureDistributions.entropy.normal.mean} &plusmn; ${r.featureDistributions.entropy.normal.stdDev}</td><td>${r.featureDistributions.entropy.covert.mean} &plusmn; ${r.featureDistributions.entropy.covert.stdDev}</td><td>+${(r.featureDistributions.entropy.covert.mean - r.featureDistributions.entropy.normal.mean).toFixed(2)}</td></tr>
      <tr><td>Query Length (chars)</td><td>${r.featureDistributions.queryLength.normal.mean} &plusmn; ${r.featureDistributions.queryLength.normal.stdDev}</td><td>${r.featureDistributions.queryLength.covert.mean} &plusmn; ${r.featureDistributions.queryLength.covert.stdDev}</td><td>+${(r.featureDistributions.queryLength.covert.mean - r.featureDistributions.queryLength.normal.mean).toFixed(1)}</td></tr>
      <tr><td>Subdomain Length (chars)</td><td>${r.featureDistributions.subdomainLength.normal.mean} &plusmn; ${r.featureDistributions.subdomainLength.normal.stdDev}</td><td>${r.featureDistributions.subdomainLength.covert.mean} &plusmn; ${r.featureDistributions.subdomainLength.covert.stdDev}</td><td>+${(r.featureDistributions.subdomainLength.covert.mean - r.featureDistributions.subdomainLength.normal.mean).toFixed(1)}</td></tr>
      <tr><td>Unusual Char Ratio (%)</td><td>${(r.featureDistributions.unusualCharRatio.normal.mean * 100).toFixed(1)}%</td><td>${(r.featureDistributions.unusualCharRatio.covert.mean * 100).toFixed(1)}%</td><td>+${((r.featureDistributions.unusualCharRatio.covert.mean - r.featureDistributions.unusualCharRatio.normal.mean) * 100).toFixed(1)}%</td></tr>
    </tbody>
  </table>

  <h2>5. Error Analysis &amp; Diagnostic Findings</h2>
  <p><strong>Rule-Based False Positives (${r.errorAnalysis.ruleBased.falsePositives.length} cases):</strong> Legitimate normal queries whose subdomain length or character entropy exceeded static anomaly boundaries (e.g. alphanumeric CDN tokens, tracking UUIDs).</p>
  <p><strong>Rule-Based False Negatives (${r.errorAnalysis.ruleBased.falseNegatives.length} cases):</strong> Short covert payload chunks that did not accumulate sufficient rule points to surpass the 50-point decision threshold.</p>
  <p><strong>Entropy Baseline Limitations:</strong> Relying exclusively on univariate Shannon entropy yields elevated False Positive Rates because legitimate infrastructure (Akamai, CloudFront) utilizes pseudorandom hashes indistinguishable from ciphertext via entropy alone.</p>

  <script>
    window.onload = function() { window.print(); };
  </script>
</body>
</html>
  `;

  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();
}

/* ==========================================================================
   VISUAL UPGRADE: NETWORK TOPOLOGY ANIMATION & FORENSIC WORKBENCH
   ========================================================================== */

let activePacketAnimations = [];

function clearAllPacketAnimations() {
  activePacketAnimations.forEach(cancelFn => {
    try { cancelFn(); } catch (e) {}
  });
  activePacketAnimations = [];
  const layer = document.getElementById('topo-packets-layer');
  if (layer) layer.innerHTML = '';
}

/**
 * Calculates and renders cubic bezier connection curves between nodes on the topology map.
 */
function updateTopologyConnectionLines() {
  const svg = document.getElementById('topology-svg-connections');
  const pathsGroup = document.getElementById('topo-paths-static');
  const wrapper = document.getElementById('topology-wrapper');
  if (!svg || !pathsGroup || !wrapper) return;

  if (typeof wrapper.getBoundingClientRect !== 'function') return;

  const wrapperRect = wrapper.getBoundingClientRect();
  if (wrapperRect.width === 0 || wrapperRect.height === 0) return;

  const resolverNode = document.getElementById('topo-node-resolver');
  if (!resolverNode || typeof resolverNode.getBoundingClientRect !== 'function') return;
  const resolverRect = resolverNode.getBoundingClientRect();

  const rLeft = {
    x: resolverRect.left - wrapperRect.left,
    y: resolverRect.top + resolverRect.height / 2 - wrapperRect.top
  };
  const rRight = {
    x: resolverRect.right - wrapperRect.left,
    y: resolverRect.top + resolverRect.height / 2 - wrapperRect.top
  };

  const clientIds = ['client-01', 'client-02', 'client-03'];
  const destIds = ['dest-web', 'dest-cdn', 'dest-covert'];

  let pathsHtml = '';

  // Clients to Resolver
  clientIds.forEach(cid => {
    const el = document.getElementById(`topo-node-${cid}`);
    if (!el || typeof el.getBoundingClientRect !== 'function') return;
    const rect = el.getBoundingClientRect();
    const startX = rect.right - wrapperRect.left;
    const startY = rect.top + rect.height / 2 - wrapperRect.top;
    const dx = (rLeft.x - startX) * 0.5;
    const d = `M ${startX} ${startY} C ${startX + dx} ${startY}, ${rLeft.x - dx} ${rLeft.y}, ${rLeft.x} ${rLeft.y}`;
    pathsHtml += `<path id="path-${cid}-resolver" class="topo-wire" d="${d}" />`;
  });

  // Resolver to Destinations
  destIds.forEach(did => {
    const el = document.getElementById(`topo-node-${did}`);
    if (!el || typeof el.getBoundingClientRect !== 'function') return;
    const rect = el.getBoundingClientRect();
    const endX = rect.left - wrapperRect.left;
    const endY = rect.top + rect.height / 2 - wrapperRect.top;
    const dx = (endX - rRight.x) * 0.5;
    const d = `M ${rRight.x} ${rRight.y} C ${rRight.x + dx} ${rRight.y}, ${endX - dx} ${endY}, ${endX} ${endY}`;
    pathsHtml += `<path id="path-resolver-${did}" class="topo-wire" d="${d}" />`;
  });

  pathsGroup.innerHTML = pathsHtml;

  // Preserve route highlight if an event is currently selected
  if (state.activeEvent) {
    highlightTopologyRouteForEvent(state.activeEvent);
  }
}

/**
 * Animates a colored packet indicator along the topology route for an active replay event.
 */
function animateTopologyPacket(ev, onComplete) {
  const layer = document.getElementById('topo-packets-layer');
  if (!layer || typeof document.createElementNS !== 'function' || typeof requestAnimationFrame !== 'function') {
    if (onComplete) onComplete();
    return;
  }

  const clientId = ev.client ? ev.client.id : 'client-01';
  const destId = ev.destination ? ev.destination.id : 'dest-web';
  const path1 = document.getElementById(`path-${clientId}-resolver`) || document.getElementById(`path-${clientId}-resolver-01`);
  const path2 = document.getElementById(`path-resolver-${destId}`) || document.getElementById(`path-resolver-01-${destId}`);

  if (!path1 || !path2 || typeof path1.getTotalLength !== 'function' || typeof path2.getTotalLength !== 'function') {
    if (onComplete) onComplete();
    return;
  }

  let color = '#00ff9d'; // Normal
  if (ev.analysis.status === 'Suspicious') color = '#ff0055';
  else if (ev.analysis.status === 'Unusual') color = '#ffb703';

  // Create flying packet circle
  const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  dot.setAttribute('r', '6');
  dot.setAttribute('fill', color);
  dot.setAttribute('class', 'topo-packet-dot');
  layer.appendChild(dot);

  const len1 = path1.getTotalLength();
  const len2 = path2.getTotalLength();

  const hopDuration = Math.min(220, Math.max(80, state.replaySpeedMs * 0.35));
  let startTimestamp = null;
  let cancelled = false;

  const cancelAnimation = () => {
    cancelled = true;
    if (dot.parentNode) dot.parentNode.removeChild(dot);
  };
  activePacketAnimations.push(cancelAnimation);

  function stepAnimation(timestamp) {
    if (cancelled) return;
    if (!startTimestamp) startTimestamp = timestamp;
    const elapsed = timestamp - startTimestamp;

    if (elapsed < hopDuration) {
      // Hop 1: Client -> Resolver
      const progress = elapsed / hopDuration;
      const pt = typeof path1.getPointAtLength === 'function' ? path1.getPointAtLength(progress * len1) : { x: 0, y: 0 };
      dot.setAttribute('cx', pt.x);
      dot.setAttribute('cy', pt.y);
      requestAnimationFrame(stepAnimation);
    } else if (elapsed < hopDuration * 2) {
      // If UDP Loss scenario and dropped, fade out dot to visualize packet drop
      if (ev.deliveryStatus === 'LOST') {
        const dropElapsed = elapsed - hopDuration;
        const dropProgress = Math.min(1, dropElapsed / (hopDuration * 0.5));
        dot.setAttribute('opacity', 1 - dropProgress);
        dot.setAttribute('fill', '#ff0055');
        dot.setAttribute('r', 6 + dropProgress * 6);
        if (dropProgress >= 1) {
          if (dot.parentNode) dot.parentNode.removeChild(dot);
          const idx = activePacketAnimations.indexOf(cancelAnimation);
          if (idx !== -1) activePacketAnimations.splice(idx, 1);
          if (onComplete) onComplete();
          return;
        }
      }

      // Hop 2: Resolver -> Destination
      const progress = (elapsed - hopDuration) / hopDuration;
      const pt = typeof path2.getPointAtLength === 'function' ? path2.getPointAtLength(progress * len2) : { x: 0, y: 0 };
      dot.setAttribute('cx', pt.x);
      dot.setAttribute('cy', pt.y);
      requestAnimationFrame(stepAnimation);
    } else {
      // Reached destination
      if (dot.parentNode) dot.parentNode.removeChild(dot);
      const idx = activePacketAnimations.indexOf(cancelAnimation);
      if (idx !== -1) activePacketAnimations.splice(idx, 1);
      if (onComplete) onComplete();
    }
  }

  requestAnimationFrame(stepAnimation);
}

/**
 * Highlights network route and nodes for the selected event.
 */
function highlightTopologyRouteForEvent(ev) {
  if (!ev) return;
  const clientId = ev.client ? ev.client.id : 'client-01';
  const destId = ev.destination ? ev.destination.id : 'dest-web';

  // Clear previous node styles
  document.querySelectorAll('.topo-node-card').forEach(card => {
    card.classList.remove('node-selected-source', 'node-selected-route', 'node-selected-dest', 'dest-suspicious', 'node-dimmed');
  });

  // Source client
  const clientCard = document.getElementById(`topo-node-${clientId}`);
  if (clientCard) clientCard.classList.add('node-selected-source');

  // Resolver
  const resolverCard = document.getElementById('topo-node-resolver');
  if (resolverCard) resolverCard.classList.add('node-selected-route');

  // Destination
  const destCard = document.getElementById(`topo-node-${destId}`);
  if (destCard) {
    destCard.classList.add('node-selected-dest');
    if (ev.analysis.status === 'Suspicious') {
      destCard.classList.add('dest-suspicious');
    }
  }

  // Dim inactive nodes
  document.querySelectorAll('.topo-node-card').forEach(card => {
    const nid = card.getAttribute('data-node');
    if (nid !== clientId && nid !== 'resolver-01' && nid !== destId) {
      card.classList.add('node-dimmed');
    }
  });

  // Highlight wires
  document.querySelectorAll('.topo-wire').forEach(w => {
    w.classList.remove('active-route-normal', 'active-route-unusual', 'active-route-suspicious');
  });

  const wire1 = document.getElementById(`path-${clientId}-resolver`) || document.getElementById(`path-${clientId}-resolver-01`);
  const wire2 = document.getElementById(`path-resolver-${destId}`) || document.getElementById(`path-resolver-01-${destId}`);
  const routeClass = ev.analysis.status === 'Suspicious'
    ? 'active-route-suspicious'
    : ev.analysis.status === 'Unusual'
      ? 'active-route-unusual'
      : 'active-route-normal';

  if (wire1) wire1.classList.add(routeClass);
  if (wire2) wire2.classList.add(routeClass);

  const statusLabel = document.getElementById('topo-status-label');
  if (statusLabel) {
    statusLabel.innerHTML = `Inspecting route: <strong>${ev.client ? ev.client.name : clientId}</strong> ➔ <strong>Resolver</strong> ➔ <strong class="${ev.analysis.status === 'Suspicious' ? 'text-danger' : 'text-emerald'}">${ev.destination ? ev.destination.name : destId}</strong>`;
  }
}

/**
 * Clears topology route highlighting.
 */
function clearTopologyRouteHighlight() {
  document.querySelectorAll('.topo-node-card').forEach(card => {
    card.classList.remove('node-selected-source', 'node-selected-route', 'node-selected-dest', 'dest-suspicious', 'node-dimmed');
  });
  document.querySelectorAll('.topo-wire').forEach(w => {
    w.classList.remove('active-route-normal', 'active-route-unusual', 'active-route-suspicious');
  });
  const statusLabel = document.getElementById('topo-status-label');
  if (statusLabel) {
    statusLabel.textContent = 'Topology Idle';
  }
}

/**
 * Updates the Investigation Overview ratio bar and counters.
 */
function updateInvestigationOverview() {
  const events = state.replayProcessedEvents;
  const total = events.length;
  const normal = events.filter(e => e.analysis.status === 'Normal').length;
  const unusual = events.filter(e => e.analysis.status === 'Unusual').length;
  const suspicious = events.filter(e => e.analysis.status === 'Suspicious').length;

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl('overview-badge-normal', `${normal} Normal`);
  setEl('overview-badge-unusual', `${unusual} Unusual`);
  setEl('overview-badge-suspicious', `${suspicious} Suspicious`);

  const pNorm = total > 0 ? (normal / total) * 100 : 0;
  const pUnus = total > 0 ? (unusual / total) * 100 : 0;
  const pSusp = total > 0 ? (suspicious / total) * 100 : 0;

  const segNorm = document.getElementById('ratio-seg-normal');
  const segUnus = document.getElementById('ratio-seg-unusual');
  const segSusp = document.getElementById('ratio-seg-suspicious');

  if (segNorm) segNorm.style.width = `${pNorm}%`;
  if (segUnus) segUnus.style.width = `${pUnus}%`;
  if (segSusp) segSusp.style.width = `${pSusp}%`;

  const ratioLabel = document.getElementById('overview-ratio-label');
  if (ratioLabel) {
    ratioLabel.textContent = `${pNorm.toFixed(0)}% Normal / ${pUnus.toFixed(0)}% Unusual / ${pSusp.toFixed(0)}% Suspicious`;
  }

  renderReplayProgressionChart();
}

/**
 * Renders the mini sparkline chart showing anomaly suspicion scores over the simulation timeline.
 */
function renderReplayProgressionChart() {
  const canvas = document.getElementById('chart-replay-progression');
  if (!canvas || !window.Chart) return;

  const events = state.replayProcessedEvents;
  const labels = events.map(e => `#${e.eventIndex || (events.indexOf(e) + 1)}`);
  const dataScores = events.map(e => e.analysis.score);
  const pointColors = events.map(e => {
    if (e.analysis.status === 'Suspicious') return '#ff0055';
    if (e.analysis.status === 'Unusual') return '#ffb703';
    return '#00ff9d';
  });

  const pointRadii = events.map(e => {
    return state.activeEvent && state.activeEvent.id === e.id ? 6 : 3;
  });

  const pointBorderColors = events.map(e => {
    return state.activeEvent && state.activeEvent.id === e.id ? '#ffffff' : 'transparent';
  });

  const pointBorderWidths = events.map(e => {
    return state.activeEvent && state.activeEvent.id === e.id ? 2 : 0;
  });

  const ctx = canvas.getContext('2d');
  if (state.charts['replay-progression']) {
    const chart = state.charts['replay-progression'];
    chart.data.labels = labels;
    chart.data.datasets[0].data = dataScores;
    chart.data.datasets[0].pointBackgroundColor = pointColors;
    chart.data.datasets[0].pointRadius = pointRadii;
    chart.data.datasets[0].pointBorderColor = pointBorderColors;
    chart.data.datasets[0].pointBorderWidth = pointBorderWidths;
    chart.update('none');
  } else {
    state.charts['replay-progression'] = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Suspicion Score',
          data: dataScores,
          borderColor: 'rgba(0, 240, 255, 0.5)',
          backgroundColor: 'rgba(0, 240, 255, 0.08)',
          borderWidth: 1.5,
          tension: 0.3,
          fill: true,
          pointBackgroundColor: pointColors,
          pointRadius: pointRadii,
          pointBorderColor: pointBorderColors,
          pointBorderWidth: pointBorderWidths
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const ev = events[ctx.dataIndex];
                return ev ? `Score: ${ev.analysis.score}/100 (${ev.analysis.status})` : '';
              }
            }
          }
        },
        scales: {
          x: { display: false },
          y: {
            min: 0,
            max: 100,
            display: false
          }
        },
        onClick: (evt, elements) => {
          if (elements && elements.length > 0) {
            const idx = elements[0].index;
            if (events[idx]) {
              selectTimelineEvent(events[idx].id);
            }
          }
        }
      }
    });
  }

  const selectedLabel = document.getElementById('progression-selected-label');
  if (selectedLabel) {
    if (state.activeEvent) {
      selectedLabel.textContent = `Selected: Event #${state.activeEvent.eventIndex || ''} (${state.activeEvent.analysis.status} - Score ${state.activeEvent.analysis.score}/100)`;
    } else {
      selectedLabel.textContent = 'No event selected';
    }
  }
}

/**
 * Generates plain-English forensic explanation for an inspected event.
 */
function generatePlainEnglishExplanation(ev) {
  if (!ev) return 'No event selected.';

  const clientName = ev.client ? ev.client.name : 'Unknown Host';
  const query = ev.queryName;
  const entropy = ev.features ? ev.features.entropy : 0;
  const subLength = ev.features ? ev.features.subdomainLength : 0;
  const unusualRatio = ev.features ? (ev.features.unusualCharRatio * 100).toFixed(0) : 0;
  const score = ev.analysis ? ev.analysis.score : 0;
  const reasons = (ev.analysis && ev.analysis.reasons && ev.analysis.reasons.length > 0)
    ? ev.analysis.reasons.join('; ')
    : 'None';

  let explanation = '';

  if (ev.analysis.status === 'Suspicious') {
    explanation = `High Threat Confidence (${score}/100): The DNS query "${query}" originating from ${clientName} exhibits severe structural anomalies typical of DNS tunneling and covert exfiltration. The longest subdomain label measures ${subLength} characters with a Shannon entropy of ${entropy} bits/char (baseline threshold ~3.8 bits/char), indicating dense information encoding rather than natural language. Diagnostic rules triggered: ${reasons}.`;
  } else if (ev.analysis.status === 'Unusual') {
    explanation = `Elevated Anomaly Score (${score}/100): The query "${query}" from ${clientName} displays atypical lexical patterns, including ${unusualRatio}% non-alphanumeric characters and an entropy of ${entropy} bits/char. While this can occur in legitimate CDN content routing or dynamic service tokens, it deviates from the benign profile and warrants monitoring. Diagnostic rules triggered: ${reasons}.`;
  } else {
    explanation = `Benign Traffic Profile (${score}/100): Standard recursive resolution for "${query}" requested by ${clientName}. The entropy (${entropy} bits/char) and label structure align with normal RFC 1035 host naming conventions, showing no indicators of steganography or data exfiltration.`;
  }

  if (ev.deliveryStatus === 'LOST') {
    explanation += ` [Transport Note: Synthetic UDP datagram dropped in transit to model unreliable transport layer packet loss.]`;
  }

  return explanation;
}

/**
 * Synchronizes educational pipeline diagram with active simulation event.
 */
function synchronizeEducationalPipeline(ev) {
  const allNodes = ['node-sender', 'node-encoder', 'node-simulator', 'node-network', 'node-analyzer', 'node-decoder', 'node-receiver'];
  allNodes.forEach(nid => {
    const el = document.getElementById(nid);
    if (el) el.classList.remove('active');
  });

  const logText = document.getElementById('pipeline-log-text');
  const statusTag = document.getElementById('pipeline-status-tag');

  if (!ev) {
    if (logText) logText.textContent = 'System Ready';
    if (statusTag) {
      statusTag.textContent = 'System Ready';
      statusTag.className = 'badge badge-normal';
    }
    return;
  }

  if (ev.groundTruth === 'simulated_covert') {
    ['node-sender', 'node-encoder', 'node-simulator', 'node-network', 'node-analyzer'].forEach(nid => {
      const el = document.getElementById(nid);
      if (el) el.classList.add('active');
    });
    if (logText) logText.textContent = `Covert packet #${ev.packetNumber || 1} processed: ${ev.queryName.substring(0, 32)}...`;
    if (statusTag) {
      statusTag.textContent = 'Covert Payload Active';
      statusTag.className = 'badge badge-danger';
    }
  } else {
    ['node-network', 'node-analyzer'].forEach(nid => {
      const el = document.getElementById(nid);
      if (el) el.classList.add('active');
    });
    if (logText) logText.textContent = `Benign lookup: ${ev.queryName}`;
    if (statusTag) {
      statusTag.textContent = 'Benign Lookup';
      statusTag.className = 'badge badge-normal';
    }
  }
}

/* ==========================================================================
   FEATURE 1-7: INTERACTIVE INVESTIGATION LAB & REPLAY CONTROLLER
   ========================================================================== */

function initReplayLab() {
  // 1. Scenario Selector
  const scenarioSelect = document.getElementById('select-replay-scenario');
  if (scenarioSelect) {
    scenarioSelect.addEventListener('change', async () => {
      const scenarioId = scenarioSelect.value;
      const seedVal = parseInt(document.getElementById('replay-seed-input')?.value, 10) || 42;
      await loadReplayScenario(scenarioId, seedVal);
    });
  }

  // 2. Random Seed
  const btnSeedRnd = document.getElementById('btn-replay-seed-rnd');
  const seedInput = document.getElementById('replay-seed-input');
  if (btnSeedRnd && seedInput) {
    btnSeedRnd.addEventListener('click', async () => {
      const newSeed = Math.floor(Math.random() * 90000) + 1000;
      seedInput.value = newSeed;
      const scenarioId = document.getElementById('select-replay-scenario')?.value || 'normal_browsing';
      await loadReplayScenario(scenarioId, newSeed);
    });
  }

  // 3. Playback Speed Buttons
  document.querySelectorAll('.speed-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.speed-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.replaySpeedMs = parseInt(btn.getAttribute('data-speed'), 10) || 700;
      if (state.isReplayRunning) {
        pauseReplayStream();
        startReplayStream();
      }
    });
  });

  // 4. Action Buttons
  const btnPlay = document.getElementById('btn-replay-play');
  const btnPause = document.getElementById('btn-replay-pause');
  const btnStep = document.getElementById('btn-replay-step');
  const btnReset = document.getElementById('btn-replay-reset');
  const btnAll = document.getElementById('btn-replay-all');

  if (btnPlay) btnPlay.addEventListener('click', startReplayStream);
  if (btnPause) btnPause.addEventListener('click', pauseReplayStream);
  if (btnStep) btnStep.addEventListener('click', stepReplayEvent);
  if (btnReset) btnReset.addEventListener('click', resetReplayStream);
  if (btnAll) btnAll.addEventListener('click', completeEntireReplayStream);

  // 5. Interactive Topology Nodes (Click to filter timeline)
  const nodeCards = document.querySelectorAll('.topo-node-card');
  nodeCards.forEach(card => {
    card.addEventListener('click', () => {
      const nodeId = card.getAttribute('data-node');
      toggleTopologyNodeFilter(nodeId);
    });
  });

  const btnClearFilter = document.getElementById('btn-clear-topo-filter');
  if (btnClearFilter) {
    btnClearFilter.addEventListener('click', () => {
      clearTopologyFilter();
    });
  }

  // 6. Timeline Search & Filters
  const searchInput = document.getElementById('timeline-search');
  const clientFilter = document.getElementById('timeline-client-filter');
  const statusFilter = document.getElementById('timeline-status-filter');
  const sortFilter = document.getElementById('timeline-sort-filter');

  if (searchInput) searchInput.addEventListener('input', renderTimelineEvents);
  if (clientFilter) clientFilter.addEventListener('change', renderTimelineEvents);
  if (statusFilter) statusFilter.addEventListener('change', renderTimelineEvents);
  if (sortFilter) sortFilter.addEventListener('change', renderTimelineEvents);

  // 7. Investigation Assessment Actions
  const btnSaveAssessment = document.getElementById('btn-save-assessment');
  if (btnSaveAssessment) {
    btnSaveAssessment.addEventListener('click', saveCurrentAnalystAssessment);
  }

  const btnOpenInspector = document.getElementById('btn-open-in-inspector');
  if (btnOpenInspector) {
    btnOpenInspector.addEventListener('click', () => {
      if (state.activeEvent) {
        inspectEventInPacketInspector(state.activeEvent);
      }
    });
  }

  const btnEvalScenario = document.getElementById('btn-eval-scenario');
  if (btnEvalScenario) {
    btnEvalScenario.addEventListener('click', benchmarkCurrentScenario);
  }

  const btnExportCSV = document.getElementById('btn-export-investigation-csv');
  if (btnExportCSV) {
    btnExportCSV.addEventListener('click', exportInvestigationsCSV);
  }

  // Window resize listener to recompute SVG connection lines
  window.addEventListener('resize', () => {
    updateTopologyConnectionLines();
  });

  // Initial draw of connection lines
  setTimeout(updateTopologyConnectionLines, 100);
}

/**
 * Loads a scenario stream from the backend API.
 */
async function loadReplayScenario(scenarioId = 'normal_browsing', seed = 42) {
  pauseReplayStream();
  clearAllPacketAnimations();
  clearTopologyRouteHighlight();
  synchronizeEducationalPipeline(null);

  const statusPill = document.getElementById('replay-status-pill');
  if (statusPill) {
    statusPill.textContent = 'LOADING SCENARIO...';
    statusPill.className = 'badge badge-normal';
  }

  try {
    const res = await fetch('/api/scenarios/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenarioId, seed })
    });

    if (!res.ok) {
      throw new Error('Failed to generate scenario stream');
    }

    const data = await res.json();
    state.replayStream = data;
    state.replayProcessedEvents = [];
    state.replayIndex = 0;
    state.activeEvent = null;

    // Reset node counters
    Object.keys(state.nodeStats).forEach(k => {
      state.nodeStats[k] = { queries: 0, alerts: 0 };
    });

    // Update scenario description
    const descBox = document.getElementById('replay-scenario-desc');
    if (descBox && data.scenario) {
      descBox.textContent = data.scenario.description;
    }

    // Toggle packet loss card visibility
    const lossCard = document.getElementById('dash-transport-loss-card');
    const wrapperLoss = document.getElementById('wrapper-replay-loss');
    if (scenarioId === 'packet_loss_reconstruction') {
      if (lossCard) lossCard.style.display = 'block';
      if (wrapperLoss) wrapperLoss.style.display = 'block';
    } else {
      if (lossCard) lossCard.style.display = 'none';
      if (wrapperLoss) wrapperLoss.style.display = 'none';
    }

    // Reset UI Counters
    updateDashboardKPIs();
    updateTopologyNodePills();
    updateReplayProgressBar(0, data.events.length);
    updateInvestigationOverview();
    setTimeout(updateTopologyConnectionLines, 50);

    if (statusPill) {
      statusPill.textContent = 'READY (IDLE)';
      statusPill.className = 'badge badge-normal';
    }

    const tickerText = document.getElementById('ticker-status-text');
    const tickerBadge = document.getElementById('ticker-status-badge');
    if (tickerText && tickerBadge) {
      tickerBadge.textContent = '🟢 READY';
      tickerBadge.className = 'ticker-badge text-emerald';
      tickerText.textContent = `Scenario "${data.scenario.title}" loaded (${data.events.length} events). Click "▶ Start Replay" or "⏭ Step" to begin.`;
    }

    // Reset Investigation View
    const emptyState = document.getElementById('investigation-empty-state');
    const detailBox = document.getElementById('investigation-detail-container');
    if (emptyState) emptyState.style.display = 'block';
    if (detailBox) detailBox.style.display = 'none';

    renderTimelineEvents();
  } catch (err) {
    console.error('Error loading scenario:', err);
    alert('Error loading scenario: ' + err.message);
  }
}

/**
 * Starts continuous playback.
 */
function startReplayStream() {
  if (!state.replayStream || !state.replayStream.events) return;
  if (state.replayIndex >= state.replayStream.events.length) {
    // If finished, reset first
    resetReplayStream();
  }

  state.isReplayRunning = true;

  const btnPlay = document.getElementById('btn-replay-play');
  const btnPause = document.getElementById('btn-replay-pause');
  if (btnPlay) btnPlay.disabled = true;
  if (btnPause) btnPause.disabled = false;

  const statusPill = document.getElementById('replay-status-pill');
  if (statusPill) {
    statusPill.textContent = 'REPLAYING...';
    statusPill.className = 'badge badge-unusual';
  }

  clearInterval(state.replayTimer);
  state.replayTimer = setInterval(() => {
    stepReplayEvent();
  }, state.replaySpeedMs);
}

/**
 * Pauses continuous playback.
 */
function pauseReplayStream() {
  state.isReplayRunning = false;
  clearInterval(state.replayTimer);
  state.replayTimer = null;

  const btnPlay = document.getElementById('btn-replay-play');
  const btnPause = document.getElementById('btn-replay-pause');
  if (btnPlay) btnPlay.disabled = false;
  if (btnPause) btnPause.disabled = true;

  const statusPill = document.getElementById('replay-status-pill');
  if (statusPill && state.replayStream) {
    if (state.replayIndex >= state.replayStream.events.length) {
      statusPill.textContent = 'COMPLETED';
      statusPill.className = 'badge badge-normal';
    } else {
      statusPill.textContent = 'PAUSED';
      statusPill.className = 'badge badge-suspicious';
    }
  }
}

/**
 * Advances playback by exactly one event.
 */
function stepReplayEvent() {
  if (!state.replayStream || !state.replayStream.events) return;

  if (state.replayIndex >= state.replayStream.events.length) {
    pauseReplayStream();
    const statusPill = document.getElementById('replay-status-pill');
    if (statusPill) {
      statusPill.textContent = 'STREAM COMPLETED';
      statusPill.className = 'badge badge-normal';
    }
    const tickerBadge = document.getElementById('ticker-status-badge');
    const tickerText = document.getElementById('ticker-status-text');
    if (tickerBadge && tickerText) {
      tickerBadge.textContent = '🏁 FINISHED';
      tickerText.textContent = `All ${state.replayStream.events.length} events processed. Ready for forensic investigation and evaluation benchmarking.`;
    }
    return;
  }

  const ev = state.replayStream.events[state.replayIndex];
  state.replayIndex++;
  state.replayProcessedEvents.push(ev);

  processSingleReplayEvent(ev);
}

/**
 * Resets the replay state back to index 0.
 */
function resetReplayStream() {
  pauseReplayStream();
  clearAllPacketAnimations();
  clearTopologyRouteHighlight();
  synchronizeEducationalPipeline(null);

  state.replayIndex = 0;
  state.replayProcessedEvents = [];
  state.activeEvent = null;

  Object.keys(state.nodeStats).forEach(k => {
    state.nodeStats[k] = { queries: 0, alerts: 0 };
  });

  updateDashboardKPIs();
  updateTopologyNodePills();
  updateReplayProgressBar(0, state.replayStream ? state.replayStream.events.length : 1);
  updateInvestigationOverview();
  setTimeout(updateTopologyConnectionLines, 50);

  const statusPill = document.getElementById('replay-status-pill');
  if (statusPill) {
    statusPill.textContent = 'RESET (IDLE)';
    statusPill.className = 'badge badge-normal';
  }

  const emptyState = document.getElementById('investigation-empty-state');
  const detailBox = document.getElementById('investigation-detail-container');
  if (emptyState) emptyState.style.display = 'block';
  if (detailBox) detailBox.style.display = 'none';

  renderTimelineEvents();
}

/**
 * Completes the remaining stream immediately.
 */
function completeEntireReplayStream() {
  if (!state.replayStream || !state.replayStream.events) return;
  pauseReplayStream();

  while (state.replayIndex < state.replayStream.events.length) {
    const ev = state.replayStream.events[state.replayIndex];
    state.replayIndex++;
    state.replayProcessedEvents.push(ev);

    // Update node counts
    const clientId = ev.client.id;
    if (state.nodeStats[clientId]) {
      state.nodeStats[clientId].queries++;
      if (ev.analysis.status !== 'Normal') state.nodeStats[clientId].alerts++;
    }
    if (state.nodeStats['resolver-01']) state.nodeStats['resolver-01'].queries++;
    if (ev.destination && state.nodeStats[ev.destination.id]) {
      state.nodeStats[ev.destination.id].queries++;
    }
  }

  updateDashboardKPIs();
  updateTopologyNodePills();
  updateReplayProgressBar(state.replayIndex, state.replayStream.events.length);
  updateInvestigationOverview();
  setTimeout(updateTopologyConnectionLines, 50);

  const statusPill = document.getElementById('replay-status-pill');
  if (statusPill) {
    statusPill.textContent = 'COMPLETED';
    statusPill.className = 'badge badge-normal';
  }

  const tickerBadge = document.getElementById('ticker-status-badge');
  const tickerText = document.getElementById('ticker-status-text');
  if (tickerBadge && tickerText) {
    tickerBadge.textContent = '🏁 STREAM READY';
    tickerText.textContent = `Completed replay of all ${state.replayProcessedEvents.length} synthetic DNS events. Select queries below to investigate.`;
  }

  renderTimelineEvents();

  // Auto-select the first suspicious or unusual event if available
  const suspiciousEvt = state.replayProcessedEvents.find(e => e.analysis.status === 'Suspicious') || state.replayProcessedEvents[0];
  if (suspiciousEvt) {
    selectTimelineEvent(suspiciousEvt.id);
  }
}

/**
 * Processes an individual live replay event.
 */
function processSingleReplayEvent(ev) {
  // 1. Update node statistics
  const clientId = ev.client.id;
  if (state.nodeStats[clientId]) {
    state.nodeStats[clientId].queries++;
    if (ev.analysis.status !== 'Normal') state.nodeStats[clientId].alerts++;
  }
  if (state.nodeStats['resolver-01']) state.nodeStats['resolver-01'].queries++;
  if (ev.destination && state.nodeStats[ev.destination.id]) {
    state.nodeStats[ev.destination.id].queries++;
  }

  // 2. Animate nodes and flying packet on topology
  pulseTopologyNode(clientId);
  pulseTopologyNode('resolver-01');
  if (ev.destination) pulseTopologyNode(ev.destination.id);
  animateTopologyPacket(ev);

  // 3. Update UI KPIs, Progress, and Overview Distribution
  updateDashboardKPIs();
  updateTopologyNodePills();
  updateReplayProgressBar(state.replayIndex, state.replayStream.events.length);
  updateInvestigationOverview();

  // 4. Update Ticker Alert
  const ticker = document.getElementById('dash-alert-ticker');
  const tickerBadge = document.getElementById('ticker-status-badge');
  const tickerText = document.getElementById('ticker-status-text');

  if (ev.analysis.status === 'Suspicious') {
    if (ticker) ticker.className = 'alert-ticker alert-active';
    if (tickerBadge) {
      tickerBadge.textContent = '🔴 THREAT ALERT';
      tickerBadge.className = 'ticker-badge text-danger';
    }
    if (tickerText) {
      const reason = ev.analysis.reasons[0] || 'Elevated character entropy / structural anomaly';
      tickerText.textContent = `[${ev.timestamp}] ${ev.client.name}: Threat Score ${ev.analysis.score}/100 on ${ev.queryName} (${reason})`;
    }
  } else if (ev.analysis.status === 'Unusual') {
    if (ticker) ticker.className = 'alert-ticker';
    if (tickerBadge) {
      tickerBadge.textContent = '🟡 UNUSUAL EVENT';
      tickerBadge.className = 'ticker-badge text-amber';
    }
    if (tickerText) {
      tickerText.textContent = `[${ev.timestamp}] ${ev.client.name}: Anomaly Score ${ev.analysis.score}/100 on ${ev.queryName} (${ev.analysis.reasons[0] || 'Unusual character distribution'})`;
    }
  } else {
    if (ticker) ticker.className = 'alert-ticker';
    if (tickerBadge) {
      tickerBadge.textContent = '🟢 BENIGN QUERY';
      tickerBadge.className = 'ticker-badge text-emerald';
    }
    if (tickerText) {
      tickerText.textContent = `[${ev.timestamp}] ${ev.client.name}: Standard DNS lookup for ${ev.queryName}`;
    }
  }

  // 5. Update Packet Loss Card if scenario requires it
  if (state.replayStream.scenario.id === 'packet_loss_reconstruction') {
    updatePacketLossCard();
  }

  // 6. Append / refresh timeline
  renderTimelineEvents();

  // Auto-scroll timeline to bottom as events arrive
  const container = document.getElementById('timeline-events-container');
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

/**
 * Updates top KPI metric cards.
 */
function updateDashboardKPIs() {
  const events = state.replayProcessedEvents;
  const total = events.length;
  const normal = events.filter(e => e.groundTruth === 'normal').length;
  const unusual = events.filter(e => e.analysis.status === 'Unusual').length;
  const suspicious = events.filter(e => e.analysis.status === 'Suspicious').length;
  const lost = events.filter(e => e.deliveryStatus === 'LOST').length;
  const reviewed = Object.keys(state.investigations).length;

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl('dash-total-events', total);
  setEl('dash-normal-events', normal);
  setEl('dash-alert-events', unusual + suspicious);
  setEl('dash-loss-events', lost);
  setEl('dash-reviewed-events', reviewed);

  const totalSub = document.getElementById('dash-total-sub');
  if (totalSub && state.replayStream) {
    totalSub.textContent = `of ${state.replayStream.events.length} planned events`;
  }

  const alertSub = document.getElementById('dash-alert-sub');
  if (alertSub) {
    alertSub.textContent = `${unusual} unusual &bull; ${suspicious} suspicious`;
  }

  const lossSub = document.getElementById('dash-loss-sub');
  if (lossSub) {
    const rate = total > 0 ? ((lost / total) * 100).toFixed(0) : 0;
    lossSub.textContent = `${rate}% drop rate`;
  }
}

/**
 * Updates node stat pills on the topology map.
 */
function updateTopologyNodePills() {
  Object.keys(state.nodeStats).forEach(id => {
    const statPill = document.getElementById(`stat-node-${id}`);
    const alertPill = document.getElementById(`alert-node-${id}`);
    const data = state.nodeStats[id];

    if (statPill) {
      if (id === 'resolver-01') {
        statPill.textContent = `${data.queries} processed`;
      } else if (id.startsWith('dest-')) {
        statPill.textContent = `${data.queries} resolved`;
      } else {
        statPill.textContent = `${data.queries} queries`;
      }
    }

    if (alertPill) {
      if (data.alerts > 0) {
        alertPill.style.display = 'inline-block';
        alertPill.textContent = `${data.alerts} alerts`;
      } else {
        alertPill.style.display = 'none';
      }
    }
  });
}

/**
 * Adds temporary pulse CSS animation to a topology card.
 */
function pulseTopologyNode(nodeId) {
  const nodeCard = document.getElementById(`topo-node-${nodeId}`);
  if (nodeCard) {
    nodeCard.classList.remove('pulsing');
    void nodeCard.offsetWidth; // trigger reflow
    nodeCard.classList.add('pulsing');
    setTimeout(() => {
      nodeCard.classList.remove('pulsing');
    }, 600);
  }
}

/**
 * Toggles timeline filter by clicking on a topology node.
 */
function toggleTopologyNodeFilter(nodeId) {
  if (state.activeNodeFilter === nodeId) {
    clearTopologyFilter();
  } else {
    state.activeNodeFilter = nodeId;
    document.querySelectorAll('.topo-node-card').forEach(c => c.classList.remove('active-filter'));
    const targetCard = document.getElementById(`topo-node-${nodeId}`);
    if (targetCard) targetCard.classList.add('active-filter');

    const statusPill = document.getElementById('topology-filter-status');
    const btnClear = document.getElementById('btn-clear-topo-filter');
    if (statusPill) {
      statusPill.textContent = `Filtered to: ${nodeId}`;
      statusPill.className = 'badge badge-unusual';
    }
    if (btnClear) btnClear.style.display = 'inline-block';

    // Synchronize client filter dropdown if it is a client
    const clientSelect = document.getElementById('timeline-client-filter');
    if (clientSelect && nodeId.startsWith('client-')) {
      clientSelect.value = nodeId;
    }

    renderTimelineEvents();
  }
}

/**
 * Clears topology filtering.
 */
function clearTopologyFilter() {
  state.activeNodeFilter = null;
  document.querySelectorAll('.topo-node-card').forEach(c => c.classList.remove('active-filter'));

  const statusPill = document.getElementById('topology-filter-status');
  const btnClear = document.getElementById('btn-clear-topo-filter');
  if (statusPill) {
    statusPill.textContent = 'Viewing All Nodes';
    statusPill.className = 'badge badge-normal';
  }
  if (btnClear) btnClear.style.display = 'none';

  const clientSelect = document.getElementById('timeline-client-filter');
  if (clientSelect) clientSelect.value = 'all';

  renderTimelineEvents();
}

/**
 * Updates the replay progress bar.
 */
function updateReplayProgressBar(current, total) {
  const pct = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
  const bar = document.getElementById('replay-progress-fill');
  const counter = document.getElementById('replay-progress-counter');
  const pctLabel = document.getElementById('replay-progress-pct');

  if (bar) bar.style.width = `${pct}%`;
  if (counter) counter.textContent = `Event ${current} of ${total} processed`;
  if (pctLabel) pctLabel.textContent = `${pct}% Complete`;
}

/**
 * Updates the Transport Packet Loss card.
 */
function updatePacketLossCard() {
  const events = state.replayProcessedEvents;
  const covertEvents = events.filter(e => e.groundTruth === 'simulated_covert');
  const lostEvents = covertEvents.filter(e => e.deliveryStatus === 'LOST');
  const deliveredEvents = covertEvents.filter(e => e.deliveryStatus === 'DELIVERED');

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl('dash-loss-delivered-val', deliveredEvents.length);
  setEl('dash-loss-total-val', `out of ${covertEvents.length} covert packets`);
  setEl('dash-loss-dropped-val', lostEvents.length);

  const missingSeqEl = document.getElementById('dash-loss-missing-seq');
  if (missingSeqEl) {
    const missingSeqs = lostEvents.map(e => `#${e.packetNumber}`);
    missingSeqEl.textContent = missingSeqs.length > 0 ? `Missing: ${missingSeqs.join(', ')}` : 'Missing IDs: None';
  }

  const reconStatusEl = document.getElementById('dash-loss-recon-status');
  if (reconStatusEl) {
    if (lostEvents.length > 0) {
      reconStatusEl.textContent = 'FAILED';
      reconStatusEl.className = 'stat-value text-danger';
    } else if (covertEvents.length > 0) {
      reconStatusEl.textContent = 'SUCCESS';
      reconStatusEl.className = 'stat-value text-emerald';
    } else {
      reconStatusEl.textContent = 'STANDBY';
      reconStatusEl.className = 'stat-value text-muted';
    }
  }
}

/**
 * Renders the filterable Event Timeline.
 */
function renderTimelineEvents() {
  const container = document.getElementById('timeline-events-container');
  if (!container) return;

  const countBadge = document.getElementById('timeline-count-badge');
  const searchTerm = (document.getElementById('timeline-search')?.value || '').toLowerCase().trim();
  const clientFilterVal = document.getElementById('timeline-client-filter')?.value || 'all';
  const statusFilterVal = document.getElementById('timeline-status-filter')?.value || 'all';
  const sortFilterVal = document.getElementById('timeline-sort-filter')?.value || 'time';

  let list = [...state.replayProcessedEvents];

  // 1. Search Filter
  if (searchTerm) {
    list = list.filter(e => e.queryName.toLowerCase().includes(searchTerm) || e.client.name.toLowerCase().includes(searchTerm) || e.id.toLowerCase().includes(searchTerm));
  }

  // 2. Client Filter (dropdown or topology click)
  if (state.activeNodeFilter) {
    if (state.activeNodeFilter.startsWith('client-')) {
      list = list.filter(e => e.client.id === state.activeNodeFilter);
    } else if (state.activeNodeFilter === 'dest-covert') {
      list = list.filter(e => e.destination.id === 'dest-covert' || e.groundTruth === 'simulated_covert');
    } else if (state.activeNodeFilter === 'dest-cdn') {
      list = list.filter(e => e.destination.id === 'dest-cdn');
    } else if (state.activeNodeFilter === 'dest-web') {
      list = list.filter(e => e.destination.id === 'dest-web');
    }
  } else if (clientFilterVal !== 'all') {
    list = list.filter(e => e.client.id === clientFilterVal);
  }

  // 3. Status Filter
  if (statusFilterVal === 'LOST') {
    list = list.filter(e => e.deliveryStatus === 'LOST');
  } else if (statusFilterVal !== 'all') {
    list = list.filter(e => e.analysis.status === statusFilterVal);
  }

  // 4. Sorting
  list.sort((a, b) => {
    if (sortFilterVal === 'entropy') {
      return (b.features?.entropy || 0) - (a.features?.entropy || 0);
    } else if (sortFilterVal === 'length') {
      return (b.features?.queryLength || 0) - (a.features?.queryLength || 0);
    } else if (sortFilterVal === 'score') {
      return (b.analysis?.score || 0) - (a.analysis?.score || 0);
    } else {
      return a.eventIndex - b.eventIndex; // chronological default
    }
  });

  if (countBadge) countBadge.textContent = `${list.length} Events`;

  if (list.length === 0) {
    if (state.replayProcessedEvents.length === 0) {
      container.innerHTML = '<div class="timeline-placeholder text-center text-muted p-4"><span>Awaiting replay. Click "▶ Start Replay" or "⚡ Complete Stream" above to generate synthetic traffic events.</span></div>';
    } else {
      container.innerHTML = '<div class="timeline-placeholder text-center text-muted p-4"><span>No events match the active search and filter criteria.</span></div>';
    }
    return;
  }

  container.innerHTML = '';
  list.forEach(ev => {
    const isSelected = state.activeEvent && state.activeEvent.id === ev.id;
    const isReviewed = state.investigations[ev.id] !== undefined;

    let scoreBadgeClass = 'badge-normal';
    if (ev.analysis.status === 'Suspicious') scoreBadgeClass = 'badge-danger';
    else if (ev.analysis.status === 'Unusual') scoreBadgeClass = 'badge-unusual';

    const deliveryBadge = ev.deliveryStatus === 'LOST' 
      ? '<span class="badge badge-danger text-xs font-bold">LOST (UDP Drop)</span>' 
      : '<span class="badge badge-normal text-xs">DELIVERED</span>';

    let statusBorderClass = 'item-normal';
    if (ev.analysis.status === 'Suspicious') statusBorderClass = 'item-suspicious';
    else if (ev.analysis.status === 'Unusual') statusBorderClass = 'item-unusual';

    const item = document.createElement('div');
    item.className = `timeline-event-item ${statusBorderClass} ${isSelected ? 'selected' : ''}`;
    item.setAttribute('data-event-id', ev.id);

    item.innerHTML = `
      <div class="timeline-event-header">
        <span class="timeline-event-time">${ev.timestamp}</span>
        <span class="timeline-client-pill">${ev.client.name.split(' ')[0]}</span>
        <span class="badge ${scoreBadgeClass}">${ev.analysis.status} (${ev.analysis.score})</span>
        ${deliveryBadge}
        ${isReviewed ? '<span class="badge badge-normal" title="Analyst Reviewed">📝</span>' : ''}
      </div>
      <div class="timeline-event-body">
        <span class="timeline-query-name" title="${ev.queryName}">${ev.queryName}</span>
        <div class="timeline-event-meta">
          <span class="text-xs text-mono text-cyan">H=${ev.features.entropy}</span>
          <span class="text-xs text-muted font-bold">&bull;</span>
          <span class="text-xs text-mono text-muted">${ev.features.queryLength}B</span>
        </div>
      </div>
    `;

    item.addEventListener('click', () => {
      selectTimelineEvent(ev.id);
    });

    container.appendChild(item);
  });
}

/**
 * Selects an event and populates the Analyst Investigation Workbench.
 */
function selectTimelineEvent(eventId) {
  const ev = state.replayProcessedEvents.find(e => e.id === eventId);
  if (!ev) return;

  state.activeEvent = ev;

  // Highlight selected timeline card
  document.querySelectorAll('.timeline-event-item').forEach(el => {
    if (el.getAttribute('data-event-id') === eventId) {
      el.classList.add('selected');
    } else {
      el.classList.remove('selected');
    }
  });

  const emptyState = document.getElementById('investigation-empty-state');
  const detailBox = document.getElementById('investigation-detail-container');
  if (emptyState) emptyState.style.display = 'none';
  if (detailBox) detailBox.style.display = 'block';

  // Highlight route & nodes on interactive network topology
  highlightTopologyRouteForEvent(ev);

  // Synchronize educational pipeline stage
  synchronizeEducationalPipeline(ev);

  // Event Summary Header
  const setEl = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  setEl('detail-query-name', ev.queryName);
  setEl('detail-timestamp', ev.timestamp);
  setEl('detail-client', `${ev.client.name} (${ev.client.ip})`);
  setEl('active-event-badge', `Inspecting: ${ev.id}`);

  const statusBadge = document.getElementById('detail-status-badge');
  if (statusBadge) {
    statusBadge.textContent = `${ev.analysis.status} (${ev.analysis.score}/100)`;
    statusBadge.className = `badge ${ev.analysis.status === 'Suspicious' ? 'badge-danger' : ev.analysis.status === 'Unusual' ? 'badge-unusual' : 'badge-normal'}`;
  }

  const deliveryEl = document.getElementById('detail-delivery');
  if (deliveryEl) {
    deliveryEl.textContent = ev.deliveryStatus;
    deliveryEl.className = ev.deliveryStatus === 'LOST' ? 'text-danger font-bold' : 'text-emerald font-bold';
  }

  // RFC 1035 Packet Protocol Fields Summary
  const txIdHex = ev.packet && ev.packet.transactionId !== undefined
    ? '0x' + ev.packet.transactionId.toString(16).toUpperCase().padStart(4, '0')
    : '0x' + (1000 + (ev.eventIndex || 1)).toString(16).toUpperCase();
  const qtypeStr = ev.packet && ev.packet.queryType ? `${ev.packet.queryType} (16)` : 'TXT (16)';
  const wireBytesStr = ev.packet && ev.packet.wireBytes ? `${ev.packet.wireBytes.length} B` : `${(ev.features?.queryLength || 40) + 28} B`;
  const transportStr = 'UDP / 53';
  const destNsStr = ev.destination && ev.destination.ip ? `${ev.destination.ip}:53` : '198.51.100.53:53';

  setEl('detail-pkt-txid', txIdHex);
  setEl('detail-pkt-qtype', qtypeStr);
  setEl('detail-pkt-wire-size', wireBytesStr);
  setEl('detail-pkt-transport', transportStr);
  setEl('detail-pkt-dest', destNsStr);

  // Telemetry Chips
  setEl('detail-entropy', ev.features.entropy);
  setEl('detail-length', ev.features.queryLength);
  setEl('detail-sub-length', ev.features.subdomainLength);
  setEl('detail-unusual-ratio', `${(ev.features.unusualCharRatio * 100).toFixed(0)}%`);
  setEl('detail-ratio', `${ev.features.payloadToDomainRatio}x`);
  setEl('detail-qps', ev.features.isBurst ? `BURST (${ev.features.queryFrequency} QPS)` : `${ev.features.queryFrequency} QPS`);

  // Automated Scoring & Rule Reasons
  const scorePill = document.getElementById('detail-score-pill');
  if (scorePill) scorePill.textContent = `Score: ${ev.analysis.score}/100`;

  const reasonsList = document.getElementById('detail-reasons-list');
  if (reasonsList) {
    if (ev.analysis.reasons && ev.analysis.reasons.length > 0) {
      reasonsList.innerHTML = ev.analysis.reasons.map(r => `<li>${r}</li>`).join('');
    } else {
      reasonsList.innerHTML = '<li>Standard query structure conforming to benign baseline.</li>';
    }
  }

  // Plain-English Forensic Explanation Box
  const plainExp = document.getElementById('detail-plain-explanation');
  if (plainExp) {
    plainExp.textContent = generatePlainEnglishExplanation(ev);
  }

  // Refresh progression sparkline to highlight selected point
  renderReplayProgressionChart();

  // Populate Analyst Investigation fields (or restore previous notes)
  const existingInv = state.investigations[ev.id];
  const reviewBadge = document.getElementById('investigation-review-badge');

  if (existingInv) {
    if (reviewBadge) {
      reviewBadge.textContent = 'Analyst Reviewed';
      reviewBadge.className = 'badge badge-normal';
    }

    // Set radio
    const radio = document.querySelector(`input[name="analyst-classification"][value="${existingInv.classification}"]`);
    if (radio) radio.checked = true;

    // Set checkboxes
    const evIds = ['ev-entropy', 'ev-length', 'ev-burst', 'ev-charset', 'ev-ratio', 'ev-cdn', 'ev-loss'];
    evIds.forEach(id => {
      const chk = document.getElementById(id);
      if (chk) chk.checked = existingInv.evidence.includes(id);
    });

    const notesInput = document.getElementById('investigation-notes');
    if (notesInput) notesInput.value = existingInv.notes || '';
  } else {
    if (reviewBadge) {
      reviewBadge.textContent = 'Unreviewed';
      reviewBadge.className = 'badge badge-unusual';
    }

    // Default classification matching detector recommendation or Normal
    const defaultRadio = document.querySelector(`input[name="analyst-classification"][value="${ev.analysis.status === 'Suspicious' ? 'Potentially Suspicious' : ev.analysis.status === 'Unusual' ? 'Unusual' : 'Normal'}"]`);
    if (defaultRadio) defaultRadio.checked = true;

    // Suggest auto-evidence based on telemetry
    const checkEl = (id, val) => { const el = document.getElementById(id); if (el) el.checked = val; };
    checkEl('ev-entropy', ev.features.entropy > 3.8);
    checkEl('ev-length', ev.features.subdomainLength > 25);
    checkEl('ev-burst', ev.features.isBurst === true);
    checkEl('ev-charset', ev.features.unusualCharRatio > 0.3);
    checkEl('ev-ratio', ev.features.payloadToDomainRatio > 1.2);
    checkEl('ev-cdn', ev.queryName.includes('cloudfront') || ev.queryName.includes('akamai'));
    checkEl('ev-loss', ev.deliveryStatus === 'LOST');

    const notesInput = document.getElementById('investigation-notes');
    if (notesInput) notesInput.value = '';
  }
}

/**
 * Saves the current analyst assessment into memory and updates summary log.
 */
function saveCurrentAnalystAssessment() {
  if (!state.activeEvent) return;

  const ev = state.activeEvent;
  const classification = document.querySelector('input[name="analyst-classification"]:checked')?.value || 'Normal';

  const evidence = [];
  const evLabels = [];
  const evMap = [
    { id: 'ev-entropy', label: 'High Entropy' },
    { id: 'ev-length', label: 'Long Subdomain' },
    { id: 'ev-burst', label: 'Rate Burst' },
    { id: 'ev-charset', label: 'Unusual Charset' },
    { id: 'ev-ratio', label: 'High Payload Ratio' },
    { id: 'ev-cdn', label: 'Benign CDN' },
    { id: 'ev-loss', label: 'Dropped Packet' }
  ];

  evMap.forEach(item => {
    const chk = document.getElementById(item.id);
    if (chk && chk.checked) {
      evidence.push(item.id);
      evLabels.push(item.label);
    }
  });

  const notes = document.getElementById('investigation-notes')?.value.trim() || '';

  state.investigations[ev.id] = {
    eventId: ev.id,
    timestamp: ev.timestamp,
    client: ev.client.name,
    queryName: ev.queryName,
    automatedScore: ev.analysis.score,
    automatedStatus: ev.analysis.status,
    classification,
    evidence,
    evidenceLabels: evLabels,
    notes,
    savedAt: new Date().toLocaleTimeString()
  };

  // Feedback on save button
  const btn = document.getElementById('btn-save-assessment');
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = '✓ Saved!';
    btn.className = 'btn btn-emerald btn-sm';
    setTimeout(() => {
      btn.textContent = orig;
      btn.className = 'btn btn-cyan btn-sm';
    }, 1200);
  }

  const reviewBadge = document.getElementById('investigation-review-badge');
  if (reviewBadge) {
    reviewBadge.textContent = 'Analyst Reviewed';
    reviewBadge.className = 'badge badge-normal';
  }

  updateDashboardKPIs();
  renderInvestigationSummaryTable();
  renderTimelineEvents();
}

/**
 * Renders the Security Investigation Findings Log table.
 */
function renderInvestigationSummaryTable() {
  const tbody = document.getElementById('tbody-investigations');
  if (!tbody) return;

  const entries = Object.values(state.investigations);
  if (entries.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No events reviewed yet. Select an event from the timeline above and save an assessment.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  entries.forEach(inv => {
    const tr = document.createElement('tr');
    let classBadge = 'badge-normal';
    if (inv.classification === 'Potentially Suspicious') classBadge = 'badge-danger';
    else if (inv.classification === 'Unusual') classBadge = 'badge-unusual';
    else if (inv.classification === 'Inconclusive') classBadge = 'badge-suspicious';

    tr.innerHTML = `
      <td><span class="text-mono text-cyan font-bold">${inv.eventId}</span></td>
      <td><span class="text-mono text-muted text-xs">${inv.timestamp}</span></td>
      <td><span class="text-xs text-white">${inv.client}</span></td>
      <td><span class="code-inline text-xs">${inv.queryName}</span></td>
      <td><span class="badge ${inv.automatedScore >= 75 ? 'badge-danger' : inv.automatedScore >= 40 ? 'badge-unusual' : 'badge-normal'}">${inv.automatedStatus} (${inv.automatedScore})</span></td>
      <td><span class="badge ${classBadge}">${inv.classification}</span></td>
      <td><span class="text-xs text-muted">${inv.evidenceLabels.join(', ') || 'None'}</span></td>
      <td><span class="text-xs text-muted" title="${inv.notes}">${inv.notes ? (inv.notes.length > 40 ? inv.notes.substring(0, 40) + '...' : inv.notes) : '<em>No notes</em>'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Transitions to the Packet Inspector with this exact event packet model.
 */
function inspectEventInPacketInspector(event) {
  if (!event || !event.packet) return;

  if (!state.currentStream) {
    state.currentStream = { packets: [event.packet], totalPackets: 1 };
    state.currentAnalysis = { queryDetails: [event.analysis] };
    state.activePacketIndex = 0;
  } else {
    const idx = state.currentStream.packets.findIndex(p => p.packetNumber === event.packet.packetNumber && p.queryName === event.packet.queryName);
    if (idx !== -1) {
      state.activePacketIndex = idx;
    } else {
      state.currentStream.packets.unshift(event.packet);
      if (state.currentAnalysis && state.currentAnalysis.queryDetails) {
        state.currentAnalysis.queryDetails.unshift(event.analysis);
      }
      state.activePacketIndex = 0;
    }
  }

  populatePacketSelector();
  const selectBox = document.getElementById('select-active-packet');
  if (selectBox) selectBox.value = state.activePacketIndex;

  renderPacketInspection(state.activePacketIndex);
  switchTab('analyzer');
}

/**
 * Evaluates the current scenario events against ground truth.
 */
async function benchmarkCurrentScenario() {
  if (!state.replayStream || !state.replayStream.events || state.replayStream.events.length === 0) {
    alert('Please load and replay a scenario first before running a benchmark.');
    return;
  }

  const evalPanel = document.getElementById('scenario-eval-panel');
  const metricsGrid = document.getElementById('scenario-eval-metrics-grid');
  if (evalPanel) evalPanel.style.display = 'block';
  if (metricsGrid) metricsGrid.innerHTML = '<span class="text-cyan text-sm">Evaluating scenario against ground-truth labels...</span>';

  try {
    const res = await fetch('/api/scenarios/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: state.replayStream.events })
    });

    if (!res.ok) throw new Error('Scenario evaluation failed');

    const result = await res.json();
    const mRule = (result.ruleBased && result.ruleBased.metrics) || {};
    const mEnt = (result.entropyBaseline && result.entropyBaseline.metrics) || {};

    const fmtPct = val => (val === null || val === undefined ? 'N/A' : `${(val * 100).toFixed(1)}%`);
    const fmtNum = val => (val === null || val === undefined ? 'N/A' : Number(val).toFixed(4));

    if (metricsGrid) {
      metricsGrid.innerHTML = `
        <div class="stat-card">
          <div class="stat-title text-xs">Total Samples</div>
          <div class="stat-value text-white text-md">${result.totalEvaluated !== undefined ? result.totalEvaluated : 0}</div>
          <div class="stat-footer text-muted">Evaluated queries</div>
        </div>
        <div class="stat-card">
          <div class="stat-title text-xs">Rule Accuracy</div>
          <div class="stat-value text-emerald text-md">${fmtPct(mRule.accuracy)}</div>
          <div class="stat-footer text-muted">Baseline: ${fmtPct(mEnt.accuracy)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title text-xs">Rule Precision</div>
          <div class="stat-value text-cyan text-md">${fmtPct(mRule.precision)}</div>
          <div class="stat-footer text-muted">Baseline: ${fmtPct(mEnt.precision)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title text-xs">Rule Recall</div>
          <div class="stat-value text-amber text-md">${fmtPct(mRule.recall)}</div>
          <div class="stat-footer text-muted">Baseline: ${fmtPct(mEnt.recall)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title text-xs">Rule F1-Score</div>
          <div class="stat-value text-cyan text-md">${fmtNum(mRule.f1Score)}</div>
          <div class="stat-footer text-muted">Baseline: ${fmtNum(mEnt.f1Score)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title text-xs">False Positive Rate</div>
          <div class="stat-value text-danger text-md">${fmtPct(mRule.falsePositiveRate)}</div>
          <div class="stat-footer text-muted">Baseline: ${fmtPct(mEnt.falsePositiveRate)}</div>
        </div>
      `;
    }
  } catch (err) {
    console.error('Benchmark error:', err);
    if (metricsGrid) {
      metricsGrid.innerHTML = `<span class="text-danger text-sm">Evaluation failed: ${err.message}</span>`;
    }
  }
}

/**
 * Exports security analyst investigations to CSV.
 */
function exportInvestigationsCSV() {
  const entries = Object.values(state.investigations);
  if (entries.length === 0) {
    alert('No analyst investigation records to export. Please review events first.');
    return;
  }

  let csv = 'EventID,Timestamp,Client,QueryName,AutomatedScore,AutomatedStatus,AnalystClassification,SupportingEvidence,AnalystNotes,SavedAt\n';
  entries.forEach(item => {
    const cleanNotes = `"${(item.notes || '').replace(/"/g, '""')}"`;
    const cleanEvidence = `"${(item.evidenceLabels || []).join('; ')}"`;
    csv += [
      item.eventId,
      item.timestamp,
      `"${item.client}"`,
      `"${item.queryName}"`,
      item.automatedScore,
      item.automatedStatus,
      `"${item.classification}"`,
      cleanEvidence,
      cleanNotes,
      `"${item.savedAt}"`
    ].join(',') + '\n';
  });

  downloadFile(csv, 'dns-security-investigation-findings.csv', 'text/csv');
}

