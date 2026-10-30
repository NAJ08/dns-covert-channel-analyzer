/**
 * End-to-End Server Integration Test
 */

const http = require('http');
const app = require('../server/server');

const TEST_PORT = 3100;
const server = app.listen(TEST_PORT, async () => {
  console.log(`Test server running on port ${TEST_PORT}`);

  try {
    // 1. Test /api/health
    const health = await getJson(`http://localhost:${TEST_PORT}/api/health`);
    console.log('[PASS] GET /api/health:', health.status);

    // 2. Test /api/encode
    const encodeRes = await postJson(`http://localhost:${TEST_PORT}/api/encode`, {
      message: 'HELLO NETWORKS',
      method: 'base64',
      chunkSize: 16
    });
    console.log(`[PASS] POST /api/encode: ${encodeRes.chunks.length} chunks generated`);

    // 3. Test /api/decode
    const decodeRes = await postJson(`http://localhost:${TEST_PORT}/api/decode`, {
      queries: encodeRes.chunks.map(c => c.queryName),
      method: 'base64',
      baseDomain: 'google.com'
    });
    console.log(`[PASS] POST /api/decode: Reconstructed "${decodeRes.decodedMessage}"`);

    // 4. Test /api/simulate
    const simRes = await postJson(`http://localhost:${TEST_PORT}/api/simulate`, {
      message: 'COMPUTER NETWORKS PROJECT',
      encoding: 'base64',
      chunkSize: 16
    });
    console.log(`[PASS] POST /api/simulate: ${simRes.packets.length} synthetic packets modeled`);

    // 5. Test /api/normal-traffic
    const normalRes = await getJson(`http://localhost:${TEST_PORT}/api/normal-traffic`);
    console.log(`[PASS] GET /api/normal-traffic: ${normalRes.queries.length} baseline queries loaded`);

    // 6. Test /api/compare
    const compRes = await postJson(`http://localhost:${TEST_PORT}/api/compare`, {
      covertPackets: simRes.packets
    });
    console.log(`[PASS] POST /api/compare: ${compRes.metrics.length} comparative metrics computed`);

    console.log('\n>>> ALL END-TO-END SERVER INTEGRATION TESTS PASSED! <<<');
  } catch (err) {
    console.error('[FAIL] Integration error:', err);
    process.exitCode = 1;
  } finally {
    server.close(() => {
      console.log('Test server closed.');
      process.exit(process.exitCode || 0);
    });
  }
});

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(payload);
    const parsedUrl = new URL(url);
    const req = http.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}
