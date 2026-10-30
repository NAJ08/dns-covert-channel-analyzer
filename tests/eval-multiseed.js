/**
 * Multi-seed evaluation summary.
 * A single seed can be lucky or unlucky (there are only a handful of covert scenarios
 * per run), so report mean ± standard deviation across many seeds instead.
 *
 * Usage: npm run eval:seeds            (20 seeds, 100 samples)
 *        node tests/eval-multiseed.js 50 300
 */
const { runExperiment } = require('../server/evaluator');

const seeds = parseInt(process.argv[2], 10) || 20;
const sampleCount = parseInt(process.argv[3], 10) || 100;

const keys = ['precision', 'recall', 'f1Score', 'falsePositiveRate'];
const acc = { ruleBased: {}, entropyBaseline: {} };
for (const d of Object.keys(acc)) keys.forEach(k => (acc[d][k] = []));

for (let seed = 1; seed <= seeds; seed++) {
  const r = runExperiment({ seed, sampleCount });
  for (const d of Object.keys(acc)) {
    for (const k of keys) {
      const v = r.detectors[d].metrics[k];
      if (v !== null && v !== undefined) acc[d][k].push(v);
    }
  }
}

const stat = a => {
  const m = a.reduce((x, y) => x + y, 0) / a.length;
  const sd = Math.sqrt(a.reduce((x, y) => x + (y - m) ** 2, 0) / a.length);
  return `${m.toFixed(3)} ± ${sd.toFixed(3)}`;
};

console.log(`Synthetic evaluation — ${seeds} seeds × ${sampleCount} samples (held-out, stratified scenario split)\n`);
console.log('Metric'.padEnd(20) + 'Rule-based (multi-feature)'.padEnd(30) + 'Entropy-only baseline');
for (const k of keys) {
  console.log(k.padEnd(20) + stat(acc.ruleBased[k]).padEnd(30) + stat(acc.entropyBaseline[k]));
}
console.log('\nNote: results describe the synthetic scenarios only, not real-world performance.');
