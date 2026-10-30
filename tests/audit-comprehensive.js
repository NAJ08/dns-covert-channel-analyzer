const fs = require('fs');
const html = fs.readFileSync('public/index.html', 'utf8');
const js = fs.readFileSync('public/script.js', 'utf8');

console.log('=== COMPREHENSIVE BUTTON AUDIT ===');

// 1. Find all buttons in HTML
const btnRegex = /<button[^>]*id=["']([^"']+)["'][^>]*>([\s\S]*?)<\/button>/gi;
let m;
const buttonsInHtml = [];
while ((m = btnRegex.exec(html)) !== null) {
  const id = m[1];
  const text = m[2].replace(/<[^>]+>/g, '').trim().replace(/\s+/g, ' ');
  buttonsInHtml.push({ id, text });
}

console.log(`Found ${buttonsInHtml.length} buttons with IDs in index.html:`);
buttonsInHtml.forEach((b, i) => console.log(`  ${i + 1}. [${b.id}] "${b.text}"`));

// 2. Check each button for event listeners in script.js
const missingListeners = [];
buttonsInHtml.forEach(btn => {
  const inJs = js.includes(`'${btn.id}'`) || js.includes(`"${btn.id}"`);
  if (!inJs) {
    missingListeners.push(btn);
  }
});

console.log(`Buttons without any reference in script.js: ${missingListeners.length}`);
missingListeners.forEach(b => console.log(`  - [${b.id}] "${b.text}"`));

// 3. Find all addEventListener targets in script.js
console.log('\n=== ALL addEventListener TARGETS IN script.js ===');
const listenerRegex = /(?:document\.getElementById\(['"]([^'"]+)['"]\)|document\.querySelector\(['"]#([^'"]+)['"]\)|const\s+(\w+)\s*=\s*document\.getElementById\(['"]([^'"]+)['"]\))\s*(?:\.addEventListener|[\s\S]{0,100}\.addEventListener)/g;

// More direct regex for getElementById('...').addEventListener
const directListenerRegex = /document\.getElementById\(['"]([^'"]+)['"]\)\.addEventListener/g;
const directListeners = [];
while ((m = directListenerRegex.exec(js)) !== null) {
  const id = m[1];
  const exists = html.includes(`id="${id}"`) || html.includes(`id='${id}'`);
  directListeners.push({ id, exists, line: js.substring(0, m.index).split('\n').length });
}

console.log(`Direct document.getElementById('...').addEventListener calls: ${directListeners.length}`);
directListeners.forEach(l => {
  if (!l.exists) {
    console.log(`  CRITICAL: L${l.line} [${l.id}] DOES NOT EXIST IN index.html!`);
  }
});

// 5. Find all document.getElementById('...').property (direct chained access)
console.log('\n=== ALL DIRECT CHAINED ACCESSES (document.getElementById(...).prop) ===');
const chainedRegex = /document\.getElementById\(['"]([^'"]+)['"]\)\.([a-zA-Z0-9_$]+)/g;
const directChained = [];
while ((m = chainedRegex.exec(js)) !== null) {
  const id = m[1];
  const prop = m[2];
  const exists = html.includes(`id="${id}"`) || html.includes(`id='${id}'`);
  const line = js.substring(0, m.index).split('\n').length;
  directChained.push({ id, prop, exists, line });
}

console.log(`Total chained accesses: ${directChained.length}`);
const dangerousChained = directChained.filter(c => !c.exists);
console.log(`Dangerous chained accesses on NON-EXISTENT IDs: ${dangerousChained.length}`);
dangerousChained.forEach(c => {
  console.log(`  CRITICAL: L${c.line} [${c.id}].${c.prop}`);
});

