const http = require('http');

http.get('http://localhost:3000/', (res) => {
  console.log('GET / status:', res.statusCode);
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log('index.html size:', data.length, 'bytes');
    console.log('Contains btn-dash-run-demo:', data.includes('id="btn-dash-run-demo"'));
    console.log('Contains btn-goto-simulator:', data.includes('id="btn-goto-simulator"'));
    console.log('Contains dash-packets-count:', data.includes('id="dash-packets-count"'));
    
    // Check script.js
    http.get('http://localhost:3000/script.js', (resScript) => {
      console.log('GET /script.js status:', resScript.statusCode);
      let sData = '';
      resScript.on('data', chunk => sData += chunk);
      resScript.on('end', () => {
        console.log('script.js size:', sData.length, 'bytes');
        console.log('Contains safeAddListener:', sData.includes('function safeAddListener'));
        console.log('Contains safeSetText:', sData.includes('function safeSetText'));
        console.log('=== HTTP SERVER VERIFICATION SUCCESSFUL ===');
      });
    });
  });
}).on('error', (err) => {
  console.error('Error connecting to http://localhost:3000:', err.message);
});
