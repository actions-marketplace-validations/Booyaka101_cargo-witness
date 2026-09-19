'use strict';
// The runtime `action.yml` declares has an expiry date. GitHub removes Node 20
// from the runners on 2026-09-23, at which point an action declaring it does
// not launch, before any of this code runs, with no fallback. This suite is
// the alarm: it goes red while there is still time to move.

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const os = require('os');

const { RUNTIMES, LEAD_DAYS, readUsing, withRuntime, checkRuntime } = require('../scripts/action-runtime');

const ACTION_YML = path.join(__dirname, '..', 'action.yml');
const VALIDATE = path.join(__dirname, '..', 'scripts', 'validate-action.js');

/** readUsing takes a path; these cases are easier to state as a string. */
function readUsingFrom(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-read-'));
  try {
    const p = path.join(dir, 'action.yml');
    fs.writeFileSync(p, body);
    return readUsing(p);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

let passed = 0;
function test(name) { passed++; console.log(`  ok  ${name}`); }
function fail(name, e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
function check(name, fn) { try { fn(); test(name); } catch (e) { fail(name, e); } }

check('action.yml declares a runtime GitHub still runs', () => {
  const using = readUsing(ACTION_YML);
  const r = checkRuntime(using);
  assert.ok(r.ok, r.reason);
});

check('the declared runtime matches the bundled main script', () => {
  const yml = fs.readFileSync(ACTION_YML, 'utf8');
  assert.match(yml, /^\s+main:\s*dist\/action\.js$/m);
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'dist', 'action.js')), 'dist/action.js is missing');
});

check('a runtime past its removal date is rejected', () => {
  assert.strictEqual(checkRuntime('node16').ok, false);
  assert.strictEqual(checkRuntime('node20', new Date('2026-09-24T00:00:00Z')).ok, false);
});

check('a runtime inside the lead window is rejected while it still works', () => {
  // 2026-09-01: node20 launches fine that day, and we want to have moved.
  const r = checkRuntime('node20', new Date('2026-09-01T00:00:00Z'));
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /2026-09-23/);
});

check('a runtime with no announced removal passes', () => {
  // Read the open runtimes out of the table rather than naming node24. The day
  // node24 gets a removal date, the test that should go red is the first one.
  // Node runtimes only: composite and docker are not interpreters and never
  // get a removal date, so including them would make the guard below unfailable.
  const open = Object.keys(RUNTIMES).filter((k) => /^node/.test(k) && RUNTIMES[k].removedOn === null);
  assert.ok(open.length, 'every Node runtime in the table has a removal date; there is nothing left to move to');
  for (const k of open) assert.strictEqual(checkRuntime(k).ok, true, k);
});

check('an unknown runtime is rejected', () => {
  // Not a plausible future runtime name: `node26` would fail here the day
  // GitHub ships it, which has nothing to do with what this asserts.
  assert.strictEqual(checkRuntime('nodejs-latest').ok, false);
  assert.strictEqual(checkRuntime(null).ok, false);
  assert.strictEqual(checkRuntime('').ok, false);
});

check('LEAD_DAYS gives real notice', () => {
  assert.ok(LEAD_DAYS >= 90, 'less than a quarter is not enough warning to ship a release');
});

check('readUsing handles quotes, comments and an absent key', () => {
  assert.strictEqual(readUsingFrom("runs:\n  using: 'node24'\n  main: x.js\n"), 'node24');
  assert.strictEqual(readUsingFrom('runs:\n  using: node24 # pinned\n  main: x.js\n'), 'node24');
  // A comment or blank line at column 0 belongs to no block, so it must not end
  // `runs:`. action-validator accepts such a file, and we used to read it as
  // declaring no runtime at all and hard-fail on a valid action.
  assert.strictEqual(readUsingFrom('runs:\n# note\n\n  using: node24\n  main: x.js\n'), 'node24');
  // `using` under some other top-level key is not the action's runtime.
  assert.strictEqual(readUsingFrom('inputs:\n  using:\n    default: node20\n'), null);
  assert.strictEqual(readUsingFrom('runs:\n  main: x.js\nbranding:\n  using: node20\n'), null);
});

check('withRuntime rewrites runs.using and nothing else', () => {
  const decoy = [
    'inputs:', '  using:', '    default: node20',
    'runs:', "  using: 'node24'", '  main: dist/action.js', '',
  ].join('\n')
  ;
  const swapped = withRuntime(decoy, 'node20');
  assert.strictEqual(readUsingFrom(swapped), 'node20');
  // The decoy input keeps its own default: only the line under `runs:` moves.
  assert.ok(swapped.includes('    default: node20'));
  assert.ok(swapped.includes("  using: 'node20'"), 'the original quote style survives');
  assert.strictEqual(withRuntime('name: x', 'node20'), 'name: x');
  assert.strictEqual(withRuntime('runs:\n# note\n  using: node24\n', 'node20'), 'runs:\n# note\n  using: node20\n');
});

check('validate-action passes the shipped action.yml', () => {
  const r = cp.spawnSync(process.execPath, [VALIDATE], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
});

check('validate-action still fails on a schema error that is not the runtime', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-badaction-'));
  const p = path.join(dir, 'action.yml');
  fs.writeFileSync(p, fs.readFileSync(ACTION_YML, 'utf8').replace(/^runs:$/m, 'bogus-top-level: 1\nruns:'));
  const r = cp.spawnSync(process.execPath, [VALIDATE, p], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.strictEqual(r.status, 1, 'a real schema error must still fail the build');
  assert.match(r.stderr, /bogus-top-level/);
});

check('validate-action does not narrow a runtime the schema already accepts', () => {
  // `using: composite` with `main:` and no `steps:` is genuinely invalid, and
  // composite is in the 0.6.0 enum. Probing it as node20 makes it validate
  // clean, so the wrapper used to pass it and blame the runtime enum.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-composite-'));
  const write = (body) => {
    const p = path.join(dir, 'action.yml');
    fs.writeFileSync(p, body);
    return cp.spawnSync(process.execPath, [VALIDATE, p], { encoding: 'utf8' });
  };
  const bad = write('name: x\ndescription: y\nruns:\n  using: composite\n  main: dist/index.js\n');
  assert.strictEqual(bad.status, 1, bad.stdout + bad.stderr);

  // And what it reports is the file's own error, not the oneOf spray the probe
  // produces by rewriting a valid composite action into an invalid node20 one.
  const noisy = write([
    'bogus-top-level: 1', 'name: x', 'description: y', 'runs:', '  using: composite',
    '  steps:', '    - run: echo hi', '      shell: bash', '',
  ].join('\n'));
  assert.strictEqual(noisy.status, 1);
  assert.match(noisy.stderr, /bogus-top-level/);
  assert.doesNotMatch(noisy.stderr, /one_of/, 'the probe invented errors from another branch of the runs oneOf');
  fs.rmSync(dir, { recursive: true, force: true });
});

check('engines.node is not below what our dependencies require', () => {
  // better-sqlite3 is a native module. On a Node it does not support it does not
  // throw, it segfaults, which reads as a phantom crash rather than a bad
  // install. Claiming a floor lower than any dependency's is how that happens.

  // The floor of a range is the lowest major any of its `||` branches allows.
  const floorOf = (range) => Math.min(...String(range).split('||').map((alt) => {
    const m = alt.match(/\d+/);
    return m ? Number(m[0]) : 0;
  }));
  assert.strictEqual(floorOf('>=22'), 22);
  assert.strictEqual(floorOf('^22 || ^24'), 22);
  assert.strictEqual(floorOf('>=20.11.0'), 20);

  const ours = require('../package.json').engines.node;
  for (const dep of ['better-sqlite3']) {
    const theirs = require(`${dep}/package.json`).engines?.node;
    if (!theirs) continue; // no declared floor is no constraint
    assert.ok(floorOf(ours) >= floorOf(theirs), `package.json says node ${ours} but ${dep} needs ${theirs}`);
  }
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
