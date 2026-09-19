'use strict';
// Simple test runner: executes each test file in its own Node process so module
// state (config base URLs read from env) never leaks between suites.
const { spawnSync } = require('child_process');
const path = require('path');

const files = [
  'differ.test.js',
  'manifest.test.js',
  'publish-age.test.js',
  'cargo-lock.test.js',
  'ci-diff.test.js',
  'units.test.js',
  'hosts.test.js',
  'integration.test.js',
  'action-runtime.test.js',
];

let failed = 0;
for (const f of files) {
  const abs = path.join(__dirname, f);
  console.log(`\n=== ${f} ===`);
  const r = spawnSync(process.execPath, [abs], { stdio: 'inherit' });
  if (r.status !== 0) failed++;
}

console.log('');
if (failed) {
  console.log(`\n${failed} test file(s) FAILED.`);
  process.exit(1);
} else {
  console.log('\nAll test files PASSED.');
}
