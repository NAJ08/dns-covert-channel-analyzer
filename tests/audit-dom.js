const fs = require('fs');
const html = fs.readFileSync('public/index.html', 'utf8');
const js = fs.readFileSync('public/script.js', 'utf8');

// Find all document.getElementById('...') occurrences
const regex = /document\.getElementById\(['"]([^'"]+)['"]\)/g;
let match;
const missingIds = new Set();
const details = [];

while ((match = regex.exec(js)) !== null) {
  const id = match[1];
  const hasInHtml = html.includes(`id="${id}"`) || html.includes(`id='${id}'`);
  if (!hasInHtml) {
    missingIds.add(id);
    const lineNum = js.substring(0, match.index).split('\n').length;
    // Check next few chars
    const snippet = js.substring(match.index, match.index + 80).replace(/\n/g, ' ');
    details.push({ id, line: lineNum, snippet });
  }
}

console.log('=== All Missing IDs Referenced in script.js ===');
console.log('Unique Missing IDs:', Array.from(missingIds));
console.log('\nDetail count:', details.length);
details.forEach(d => {
  console.log(`L${d.line} [${d.id}]: ${d.snippet}`);
});
