const fs = require('fs');
const html = fs.readFileSync('public/index.html', 'utf8');
const js = fs.readFileSync('public/script.js', 'utf8');

// Find all document.querySelector('...') occurrences
const regex = /document\.querySelector\(['"]([^'"]+)['"]\)/g;
let match;
while ((match = regex.exec(js)) !== null) {
  const sel = match[1];
  console.log(`querySelector: ${sel}`);
}
