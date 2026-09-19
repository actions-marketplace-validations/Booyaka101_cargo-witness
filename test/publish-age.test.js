'use strict';
// Publish-age gate: the duration grammar, the evaluation, the .cargo/config.toml
// round trip, and an offline end-to-end run over fixtures for each edge case the
// gate has to get right — including a crate whose git side cannot be resolved,
// which is the case that proves the gate does not depend on the diff lanes.

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const tar = require('tar');

const {
  parseDuration, DurationError, evaluatePublishAge, isExcluded, formatAge, formatStamp, KEY,
} = require('../src/publish-age');
const { readCargoConfig, writeCargoConfig, cargoToolchain } = require('../src/cargo-config');

let passed = 0;
function ok(name) { passed++; console.log(`  ok  ${name}`); }
function fail(name, e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
async function test(name, fn) {
  try { await fn(); ok(name); } catch (e) { fail(name, e); }
}

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const tmp = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `cw-${tag}-`));
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

async function main() {
  // --- duration grammar (cargo's own vectors, src/util/time_span.rs) --------

  await test("parseDuration matches cargo's accepted spans", () => {
    const secs = (s) => parseDuration(s).seconds;
    assert.strictEqual(secs('0 seconds'), 0);
    assert.strictEqual(secs('1second'), 1);
    assert.strictEqual(secs('23 seconds'), 23);
    assert.strictEqual(secs('5 minutes'), 300);
    assert.strictEqual(secs('2 hours'), 7200);
    assert.strictEqual(secs('1 day'), 86400);
    assert.strictEqual(secs('24 hours'), 86400);
    assert.strictEqual(secs('2 weeks'), 1209600);
    assert.strictEqual(secs('6 months'), 2629746 * 6);
    assert.strictEqual(parseDuration('7 days').ms, 7 * DAY);
  });

  await test('parseDuration rejects exactly what cargo rejects', () => {
    for (const bad of ['', '1', 'second', '+2 seconds', 'day', '-1 days', '1.5 days',
      '1 dayz', 'always', 'never', '1 day ', ' 1 day', '1  second']) {
      assert.throws(() => parseDuration(bad), DurationError, `should reject ${JSON.stringify(bad)}`);
    }
  });

  await test('"0" is the documented disable value, not an error', () => {
    assert.strictEqual(parseDuration('0').ms, 0);
  });

  await test('the parse error names the RFC 3923 units', () => {
    try {
      parseDuration('1 fortnight');
      assert.fail('should throw');
    } catch (e) {
      for (const u of ['seconds', 'minutes', 'hours', 'days', 'weeks', 'months']) {
        assert.ok(e.message.includes(u), `error should name ${u}: ${e.message}`);
      }
    }
  });

  // --- evaluation ----------------------------------------------------------

  const NOW = Date.parse('2026-09-08T12:00:00Z');
  const ago = (ms) => new Date(NOW - ms).toISOString();

  await test('a version younger than the threshold is gated', () => {
    const ev = evaluatePublishAge(ago(40 * 60 * 1000), DAY, NOW);
    assert.strictEqual(ev.state, 'gated');
    assert.strictEqual(ev.ageMs, 40 * 60 * 1000);
    assert.strictEqual(ev.clearsAtMs, NOW - 40 * 60 * 1000 + DAY);
  });

  await test('a version exactly at the threshold is NOT gated', () => {
    assert.strictEqual(evaluatePublishAge(ago(DAY), DAY, NOW).state, 'cleared');
    assert.strictEqual(evaluatePublishAge(ago(DAY - 1), DAY, NOW).state, 'gated');
  });

  await test('no publish time is unchecked, never gated', () => {
    for (const missing of [null, undefined, '']) {
      assert.strictEqual(evaluatePublishAge(missing, DAY, NOW).state, 'unchecked');
    }
    assert.strictEqual(evaluatePublishAge('not-a-date', DAY, NOW).state, 'unchecked');
  });

  await test('age is recomputed from the absolute timestamp, never carried', () => {
    const at = ago(0);
    assert.strictEqual(evaluatePublishAge(at, HOUR, NOW).state, 'gated');
    assert.strictEqual(evaluatePublishAge(at, HOUR, NOW + 2 * HOUR).state, 'cleared');
  });

  await test('a future publish time is zero seconds old, so "0" still clears it', () => {
    const future = new Date(NOW + HOUR).toISOString();
    assert.strictEqual(evaluatePublishAge(future, 0, NOW).state, 'cleared');
    assert.strictEqual(evaluatePublishAge(future, 0, NOW).ageMs, 0);
    // With a real threshold an unaged version is still gated: the conservative
    // direction when a clock is wrong.
    assert.strictEqual(evaluatePublishAge(future, DAY, NOW).state, 'gated');
  });

  await test('exemptions match bare name and name@version', () => {
    assert.strictEqual(isExcluded(['foo'], 'foo', '1.2.3'), true);
    assert.strictEqual(isExcluded(['foo@1.2.3'], 'foo', '1.2.3'), true);
    assert.strictEqual(isExcluded(['foo@9.9.9'], 'foo', '1.2.3'), false);
    assert.strictEqual(isExcluded([], 'foo', '1.2.3'), false);
  });

  await test('formatters render the shapes the report prints', () => {
    assert.strictEqual(formatAge(40 * 60 * 1000), '40m');
    assert.strictEqual(formatAge(45 * 1000), '45s');
    assert.strictEqual(formatAge(3 * HOUR + 12 * 60 * 1000), '3h 12m');
    assert.strictEqual(formatAge(9 * DAY), '9d');
    assert.strictEqual(formatStamp(Date.parse('2026-09-08T08:32:11Z')), '2026-09-08 08:32Z');
  });

  // --- .cargo/config.toml --------------------------------------------------

  await test('writes the key into a file that does not exist yet', () => {
    const p = path.join(tmp('cfg1'), '.cargo', 'config.toml');
    const res = writeCargoConfig(p, '7 days', []);
    assert.strictEqual(res.created, true);
    assert.strictEqual(res.previous, null);
    assert.strictEqual(fs.readFileSync(p, 'utf8'), '[registry]\nglobal-min-publish-age = "7 days"\n');
  });

  await test('rewrites the value, keeping every other key, comment, blank line and CRLF', () => {
    const p = path.join(tmp('cfg2'), 'config.toml');
    const before =
      '# my cargo config\r\n[build]\r\njobs = 4   # keep two cores free\r\n\r\n' +
      '[registry]\r\n# token lives in credentials.toml\r\nglobal-min-publish-age = "3 days"\r\n\r\n' +
      '[net]\r\nretry = 3\r\n';
    fs.writeFileSync(p, before);
    const res = writeCargoConfig(p, '14 days', []);
    assert.strictEqual(res.previous, '3 days');
    const after = fs.readFileSync(p, 'utf8');
    assert.strictEqual(after, before.replace('"3 days"', '"14 days"'));
    assert.ok(after.includes('\r\n'), 'CRLF must survive');
    assert.ok(after.includes('# keep two cores free'));
  });

  await test('adds the key under an existing [registry] table', () => {
    const p = path.join(tmp('cfg3'), 'config.toml');
    fs.writeFileSync(p, '[registry]\ndefault = "crates-io"\n');
    writeCargoConfig(p, '1 day', []);
    assert.strictEqual(fs.readFileSync(p, 'utf8'),
      '[registry]\nglobal-min-publish-age = "1 day"\ndefault = "crates-io"\n');
  });

  await test('appends a [registry] table when the file has none', () => {
    const p = path.join(tmp('cfg4'), 'config.toml');
    fs.writeFileSync(p, '[net]\nretry = 3\n');
    writeCargoConfig(p, '1 week', []);
    assert.strictEqual(fs.readFileSync(p, 'utf8'),
      '[net]\nretry = 3\n\n[registry]\nglobal-min-publish-age = "1 week"\n');
  });

  await test('exemptions round-trip through the marker comment', () => {
    const p = path.join(tmp('cfg5'), 'config.toml');
    writeCargoConfig(p, '7 days', ['internal-crate', 'hotfix@2.1.0']);
    const back = readCargoConfig(p);
    assert.strictEqual(back.value, '7 days');
    assert.deepStrictEqual(back.excludes, ['internal-crate', 'hotfix@2.1.0']);
    const once = fs.readFileSync(p, 'utf8');
    writeCargoConfig(p, '7 days', ['internal-crate', 'hotfix@2.1.0']);
    assert.strictEqual(fs.readFileSync(p, 'utf8'), once, 'a second write must be byte-identical');
  });

  await test('a value with a trailing comment is read and replaced cleanly', () => {
    const p = path.join(tmp('cfg6'), 'config.toml');
    fs.writeFileSync(p, '[registry]\nglobal-min-publish-age = "2 days" # set by hand\n');
    assert.strictEqual(readCargoConfig(p).value, '2 days');
    writeCargoConfig(p, '5 days', []);
    assert.strictEqual(readCargoConfig(p).value, '5 days');
  });

  await test('a resolver gate set to "allow" is read and reported, never rewritten', async () => {
    const p = path.join(tmp('cfg8'), 'config.toml');
    const before = '[resolver]\nincompatible-publish-age = "allow"\n\n[registry]\nglobal-min-publish-age = "1 day"\n';
    fs.writeFileSync(p, before);
    assert.strictEqual(readCargoConfig(p).resolverMode, 'allow');
    writeCargoConfig(p, '7 days', []);
    assert.strictEqual(fs.readFileSync(p, 'utf8'), before.replace('"1 day"', '"7 days"'),
      'only the threshold may change');
    assert.strictEqual(readCargoConfig(p).resolverMode, 'allow');
  });

  await test('reads and rewrites the top-level dotted spelling in place', () => {
    const p = path.join(tmp('cfg9'), 'config.toml');
    const before = 'net.retry = 3\nregistry.global-min-publish-age = "2 days"\n';
    fs.writeFileSync(p, before);
    const st = readCargoConfig(p);
    assert.strictEqual(st.value, '2 days');
    assert.strictEqual(st.dotted, true);
    const res = writeCargoConfig(p, '9 days', []);
    assert.strictEqual(res.dotted, true);
    const after = fs.readFileSync(p, 'utf8');
    assert.strictEqual(after, before.replace('"2 days"', '"9 days"'));
    assert.ok(!after.includes('[registry]'), 'must not add a table');
  });

  await test('never appends [registry] to a file that already uses registry. dotted keys', () => {
    // TOML forbids re-opening a table defined by dotted keys, and cargo then
    // refuses to load the whole config (verified: exit 101 on cargo 1.95).
    const p = path.join(tmp('cfg10'), 'config.toml');
    fs.writeFileSync(p, 'registry.default = "crates-io"\n');
    const res = writeCargoConfig(p, '3 days', []);
    assert.strictEqual(res.dotted, true);
    const after = fs.readFileSync(p, 'utf8');
    assert.ok(!after.includes('[registry]'), after);
    assert.ok(after.includes('registry.global-min-publish-age = "3 days"'), after);
    assert.strictEqual(readCargoConfig(p).value, '3 days');
  });

  await test('dotted spacing and a dotted resolver key are both understood', () => {
    const p = path.join(tmp('cfg11'), 'config.toml');
    fs.writeFileSync(p,
      'registry . global-min-publish-age = "4 days"\nresolver.incompatible-publish-age = "allow"\n');
    const st = readCargoConfig(p);
    assert.strictEqual(st.value, '4 days');
    assert.strictEqual(st.resolverMode, 'allow');
  });

  await test('a key outside [registry] is not mistaken for the policy', () => {
    const p = path.join(tmp('cfg7'), 'config.toml');
    fs.writeFileSync(p, '[registries.internal]\nglobal-min-publish-age = "99 days"\n');
    assert.strictEqual(readCargoConfig(p).value, null);
  });

  await test('cargoToolchain reports the installed cargo, or says it could not', () => {
    const t = cargoToolchain();
    assert.ok(t.enforces === null || typeof t.enforces === 'boolean');
    if (t.enforces !== null) {
      assert.ok(/^\d+\.\d+\.\d+$/.test(t.version), t.version);
      // 1.100 is where cargo starts enforcing these keys (rust-lang/cargo#17335).
      assert.strictEqual(t.enforces, t.major > 1 || (t.major === 1 && t.minor >= 100));
    } else {
      assert.ok(t.error, 'an unreadable toolchain must carry a reason');
    }
  });

  await endToEnd();

  console.log(`\n${passed} assertions passed.`);
  console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
}

/**
 * Offline end to end. The mock answers only what this lane needs: version
 * metadata carrying created_at, the .crate on the CDN, and a git tree served
 * for the refs a fixture declares (so a fixture can declare none).
 */
async function endToEnd() {
  const R = {};
  const now = Date.now();
  const SRC = 'pub fn a(){}';

  async function add(name, version, { publishedMsAgo, files, repo, tag, gitFiles, noCreatedAt }) {
    const dir = tmp('build');
    const top = path.join(dir, `${name}-${version}`);
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(top, rel)), { recursive: true });
      fs.writeFileSync(path.join(top, rel), content);
    }
    const cratePath = path.join(dir, 'c.crate');
    await tar.create({ gzip: true, file: cratePath, cwd: dir }, [`${name}-${version}`]);
    const buf = fs.readFileSync(cratePath);
    fs.rmSync(dir, { recursive: true, force: true });
    R[`${name}@${version}`] = {
      buf,
      sha: crypto.createHash('sha256').update(buf).digest('hex'),
      createdAt: noCreatedAt ? null : new Date(now - publishedMsAgo).toISOString(),
      repo,
      tag,
      gitFiles: gitFiles || {},
    };
  }

  const crateFiles = (name, extra = {}) =>
    ({ 'Cargo.toml': `[package]\nname = "${name}"\n`, 'src/lib.rs': SRC, ...extra });

  // 40 minutes old: inside any threshold anyone would set.
  await add('fresh', '1.2.3', {
    publishedMsAgo: 40 * 60 * 1000,
    files: crateFiles('fresh'),
    repo: 'https://github.com/acme/fresh', tag: 'v1.2.3', gitFiles: crateFiles('fresh'),
  });
  // Exactly at the 24-hour threshold the run uses.
  await add('boundary', '1.0.0', {
    publishedMsAgo: DAY,
    files: crateFiles('boundary'),
    repo: 'https://github.com/acme/boundary', tag: 'v1.0.0', gitFiles: crateFiles('boundary'),
  });
  // A registry that publishes no time: unchecked, never blocked.
  await add('notime', '1.0.0', {
    noCreatedAt: true,
    files: crateFiles('notime'),
    repo: 'https://github.com/acme/notime', tag: 'v1.0.0', gitFiles: crateFiles('notime'),
  });
  // Fresh, and its git side cannot be resolved: no tag, no commit, nothing to
  // diff against. The gate must still fire — that is the whole point.
  await add('nogit', '2.0.0', {
    publishedMsAgo: 30 * 60 * 1000,
    files: crateFiles('nogit'),
    repo: 'https://github.com/acme/nogit', tag: null, gitFiles: {},
  });
  // Fresh AND diverging: the arrayref-wave shape, and the combination the
  // report has to call out on one line.
  await add('evil', '0.3.10', {
    publishedMsAgo: 40 * 60 * 1000,
    files: crateFiles('evil', { 'build.rs': 'fn main(){ exfil(); }' }),
    repo: 'https://github.com/acme/evil', tag: 'v0.3.10', gitFiles: crateFiles('evil'),
  });

  const gitBlobSha = (buf) => {
    const h = crypto.createHash('sha1');
    h.update(`blob ${buf.length}\0`);
    h.update(buf);
    return h.digest('hex');
  };
  const findRef = (owner, repo, ref) => Object.values(R)
    .find((e) => e.repo === `https://github.com/${owner}/${repo}` && e.tag === ref);

  const server = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    let m;
    if ((m = url.match(/^\/api\/v1\/crates\/([^/]+)\/([^/?]+)$/))) {
      const e = R[`${m[1]}@${m[2]}`];
      if (!e) { res.writeHead(404); return res.end('{}'); }
      const version = { repository: e.repo, checksum: e.sha, yanked: false };
      if (e.createdAt) version.created_at = e.createdAt;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ version }));
    }
    if ((m = url.match(/^\/api\/v1\/crates\/([^/?]+)$/))) {
      const exists = Object.keys(R).some((k) => k.startsWith(`${m[1]}@`));
      res.writeHead(exists ? 200 : 404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ crate: { name: m[1] } }));
    }
    if ((m = url.match(/^\/crates\/([^/]+)\/([^/]+)\.crate$/))) {
      // Split on the known name rather than with `([^/]+)-([^/]+)`, which
      // backtracks quadratically on a dash-heavy segment (js/polynomial-redos).
      const prefix = `${m[1]}-`;
      const e = m[2].startsWith(prefix) ? R[`${m[1]}@${m[2].slice(prefix.length)}`] : null;
      if (!e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': 'application/gzip' });
      return res.end(e.buf);
    }
    if ((m = url.match(/^\/repos\/([^/]+)\/([^/]+)\/git\/trees\/([^/?]+)/))) {
      const e = findRef(m[1], m[2], m[3]);
      if (!e) { res.writeHead(404); return res.end('{"message":"Not Found"}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        tree: Object.entries(e.gitFiles).map(([p, c]) => ({
          path: p, type: 'blob', sha: gitBlobSha(Buffer.from(c)),
        })),
        truncated: false,
      }));
    }
    if ((m = url.match(/^\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/))) {
      const e = findRef(m[1], m[2], m[3]);
      const content = e && e.gitFiles[m[4]];
      if (content == null) { res.writeHead(404); return res.end(); }
      res.writeHead(200);
      return res.end(content);
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.CARGO_WITNESS_CRATES_API = `${base}/api/v1`;
  process.env.CARGO_WITNESS_CRATES_STATIC = base;
  process.env.CARGO_WITNESS_GITHUB_API = base;
  process.env.CARGO_WITNESS_GITHUB_RAW = base;
  process.env.CARGO_WITNESS_NO_NOTIFY = '1';

  const { runScan } = require('../src/scanner');
  const { createMemoryStore } = require('../src/store');
  const { toSarif } = require('../src/sarif');
  const { printPublishAge } = require('../src/report');

  const ALL = [
    { name: 'fresh', version: '1.2.3' }, { name: 'boundary', version: '1.0.0' },
    { name: 'notime', version: '1.0.0' }, { name: 'nogit', version: '2.0.0' },
    { name: 'evil', version: '0.3.10' },
  ];
  const gate = (excludes = []) => ({ raw: '24 hours', ms: DAY, excludes });
  const scan = (packages, publishAge, extra = {}) =>
    runScan({ packages, db: createMemoryStore(), log: () => {}, publishAge, ...extra });
  const flagsOf = (r) => (r.flags || []).map((f) => f.flag);
  const section = (summary) => {
    let out = '';
    printPublishAge(summary, { log: (m) => { out += m + '\n'; } });
    return plain(out);
  };

  /** Age every stored row past the 24h re-check window. */
  const staleAll = (db) =>
    db._db.prepare('UPDATE packages SET meta_checked_at = ?').run(Date.now() - 25 * 3600 * 1000);

  const withGate = await scan(ALL, gate());
  const by = {};
  for (const r of withGate.results) by[r.name] = r;

  await test('a 40-minute-old pin is gated and SUSPICIOUS', () => {
    assert.strictEqual(by.fresh.status, 'SUSPICIOUS', JSON.stringify(by.fresh));
    assert.ok(flagsOf(by.fresh).includes('PUBLISH_AGE'));
    assert.strictEqual(by.fresh.publishAge.state, 'gated');
    const f = by.fresh.flags.find((x) => x.flag === 'PUBLISH_AGE');
    assert.strictEqual(f.severity, 'medium');
    assert.ok(f.detail.includes('24 hours'), f.detail);
    assert.ok(f.detail.includes(KEY), f.detail);
    assert.ok(f.detail.includes('arrayref@0.3.10'), f.detail);
  });

  await test('a pin exactly at the threshold clears it', () => {
    assert.strictEqual(by.boundary.publishAge.state, 'cleared');
    assert.ok(!flagsOf(by.boundary).includes('PUBLISH_AGE'));
    assert.strictEqual(by.boundary.status, 'CLEAN', JSON.stringify(by.boundary));
  });

  await test('a version with no created_at is unchecked, not blocked', () => {
    assert.strictEqual(by.notime.publishAge.state, 'unchecked');
    assert.ok(!flagsOf(by.notime).includes('PUBLISH_AGE'));
    assert.strictEqual(by.notime.status, 'CLEAN', JSON.stringify(by.notime));
    assert.ok(by.notime.publishAge.reason.includes('no publish time'));
  });

  await test('the gate still fires when the git side cannot be resolved', () => {
    assert.strictEqual(by.nogit.status, 'SUSPICIOUS', JSON.stringify(by.nogit));
    // Nothing was comparable, so no divergence lane could have produced this.
    assert.deepStrictEqual(flagsOf(by.nogit), ['PUBLISH_AGE']);
  });

  await test('young AND diverging is reported as one combined entry', () => {
    assert.strictEqual(by.evil.status, 'SUSPICIOUS');
    assert.deepStrictEqual(flagsOf(by.evil).sort(), ['BUILD_RS_INJECTED', 'PUBLISH_AGE']);
    const entry = withGate.publishAge.gated.find((g) => g.name === 'evil');
    assert.deepStrictEqual(entry.alsoFlagged.map((f) => f.flag), ['BUILD_RS_INJECTED']);
    const out = section(withGate.publishAge);
    assert.ok(/evil@0\.3\.10\s+[\dhms ]+ old\s+clears /.test(out), out);
    assert.ok(out.includes('already flagged BUILD_RS_INJECTED'), out);
    assert.strictEqual(out.split('\n').filter((l) => l.includes('evil@0.3.10')).length, 1,
      'the combination must be one entry, not two findings');
  });

  await test('the section names the threshold, the config key and the escape hatches', () => {
    const out = section(withGate.publishAge);
    assert.ok(out.includes('PUBLISH_AGE (3)'), out);
    assert.ok(out.includes(`threshold 24 hours (${KEY})`), out);
    assert.ok(out.includes('--min-publish-age-exclude'), out);
    assert.ok(out.includes('append-only-vec@0.1.9'), out);
    assert.ok(out.includes('no registry publish time'), out);
    assert.ok(out.split('\n').every((l) => l.length <= 80), 'section must fit 80 columns');
  });

  await test('an age-only report does not read as if divergence was found', () => {
    const { printReport } = require('../src/report');
    const { createMemoryStore } = require('../src/store');
    const store = createMemoryStore();
    store.recordPackage({
      name: 'fresh', version: '1.2.3', status: 'SUSPICIOUS',
      flags: [{ flag: 'PUBLISH_AGE', file: null, severity: 'medium' }],
    });
    const real = console.log;
    let out = '';
    console.log = (m) => { out += m + '\n'; };
    try { printReport(store); } finally { console.log = real; }
    out = plain(out);
    assert.ok(out.includes('newer than the configured minimum publish age'), out);
    assert.ok(out.includes('Nothing here says they are malicious'), out);
    assert.ok(!out.includes('Investigate before building'), out);

    // A divergence finding alongside it restores the original wording.
    store.recordPackage({
      name: 'evil', version: '0.3.10', status: 'SUSPICIOUS',
      flags: [{ flag: 'BUILD_RS_INJECTED', file: 'build.rs', severity: 'high' }],
    });
    out = '';
    console.log = (m) => { out += m + '\n'; };
    try { printReport(store); } finally { console.log = real; }
    assert.ok(plain(out).includes('Investigate before building'), out);
  });

  await test('a very long crate name still fits 80 columns', () => {
    const now = Date.now();
    const long = 'a-really-quite-extraordinarily-long-crate-name-from-the-tail';
    const entry = (name) => ({
      name, version: '1.0.0', publishedMs: now - 60000, ageMs: 60000,
      clearsAtMs: now - 60000 + DAY, alsoFlagged: [],
    });
    const out = section({
      threshold: '24 hours', thresholdMs: DAY, key: KEY, excludes: [],
      gatedCount: 2, uncheckedCount: 0, excludedCount: 0, clearedCount: 0,
      unchecked: [], excluded: [],
      gated: [entry(long), entry('short')],
    });
    assert.ok(out.includes(`${long}@1.0.0`), out);
    assert.ok(out.includes('clears '), out);
    for (const line of out.split('\n')) {
      assert.ok(line.length <= 80, `line over 80 columns (${line.length}): ${line}`);
    }
  });

  await test('a positive info flag does not make an age-only report claim divergence', () => {
    const { printReport } = require('../src/report');
    const { createMemoryStore } = require('../src/store');
    const store = createMemoryStore();
    // The real shape this got wrong: attested via Trusted Publishing, verified
    // clean against the attested commit, and simply too young.
    store.recordPackage({
      name: 'attested-but-young', version: '0.47.10', status: 'SUSPICIOUS',
      flags: [
        { flag: 'PUBLISH_AGE', file: null, severity: 'medium' },
        { flag: 'TRUSTED_PUBLISH', file: '4873ee5', severity: 'info' },
      ],
    });
    const real = console.log;
    let out = '';
    console.log = (m) => { out += m + '\n'; };
    try { printReport(store); } finally { console.log = real; }
    out = plain(out);
    assert.ok(out.includes('newer than the configured minimum publish age'), out);
    assert.ok(!out.includes('Investigate before building'), out);
  });

  await test('the summary counts every bucket', () => {
    const s = withGate.publishAge;
    assert.strictEqual(s.threshold, '24 hours');
    assert.strictEqual(s.key, KEY);
    assert.strictEqual(s.gatedCount, 3);   // fresh, nogit, evil
    assert.strictEqual(s.clearedCount, 1); // boundary
    assert.strictEqual(s.uncheckedCount, 1);
    assert.strictEqual(s.excludedCount, 0);
  });

  await test('--min-publish-age-exclude exempts by name and by name@version', async () => {
    const r = await scan(ALL, gate(['fresh', 'evil@0.3.10']));
    const m = {};
    for (const x of r.results) m[x.name] = x;
    assert.strictEqual(m.fresh.publishAge.state, 'excluded');
    assert.strictEqual(m.fresh.status, 'CLEAN', JSON.stringify(m.fresh));
    assert.strictEqual(m.evil.publishAge.state, 'excluded');
    assert.deepStrictEqual(flagsOf(m.evil), ['BUILD_RS_INJECTED']); // other lanes untouched
    assert.strictEqual(r.publishAge.excludedCount, 2);
  });

  await test('the allowlist suppresses PUBLISH_AGE by name and by name@version', async () => {
    const byName = await scan([{ name: 'fresh', version: '1.2.3' }], gate(),
      { allowRules: [{ name: 'fresh', flag: 'PUBLISH_AGE' }] });
    assert.strictEqual(byName.results[0].status, 'CLEAN', JSON.stringify(byName.results[0]));
    assert.strictEqual(byName.suppressedCount, 1);

    const byVer = await scan([{ name: 'fresh', version: '1.2.3' }], gate(),
      { allowRules: [{ name: 'fresh', version: '1.2.3', flag: 'PUBLISH_AGE' }] });
    assert.strictEqual(byVer.results[0].status, 'CLEAN');

    const otherVer = await scan([{ name: 'fresh', version: '1.2.3' }], gate(),
      { allowRules: [{ name: 'fresh', version: '9.9.9', flag: 'PUBLISH_AGE' }] });
    assert.strictEqual(otherVer.results[0].status, 'SUSPICIOUS');
  });

  await test('threshold "0" gates nothing', async () => {
    const r = await scan(ALL, { raw: '0', ms: 0, excludes: [] });
    assert.strictEqual(r.publishAge.gatedCount, 0);
    assert.strictEqual(r.suspicious.filter((s) => s.name === 'fresh').length, 0);
  });

  await test('SARIF: warning alone, error when combined with a high flag', () => {
    const sarif = toSarif(withGate.suspicious, 'Cargo.lock');
    const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'PUBLISH_AGE');
    assert.ok(rule, 'missing SARIF rule PUBLISH_AGE');
    assert.strictEqual(rule.defaultConfiguration.level, 'warning');
    const results = sarif.runs[0].results.filter((r) => r.ruleId === 'PUBLISH_AGE');
    assert.strictEqual(results.find((r) => r.properties.package === 'fresh').level, 'warning');
    assert.strictEqual(results.find((r) => r.properties.package === 'evil').level, 'error');
  });

  // The regression that matters most: with the flag absent, nothing changes.
  await test('flag absent -> no publishAge anywhere, no PUBLISH_AGE flag', async () => {
    const r = await scan(ALL, null);
    assert.strictEqual(r.publishAge, null);
    for (const x of r.results) {
      assert.strictEqual(x.publishAge, undefined, `${x.name} leaked a publishAge`);
      assert.ok(!flagsOf(x).includes('PUBLISH_AGE'), `${x.name} leaked PUBLISH_AGE`);
    }
    assert.deepStrictEqual(r.suspicious.map((s) => s.name), ['evil']);
  });

  // Git and path dependencies never reach the gate: the lockfile parser keeps
  // only `registry+` entries, and RFC 3923 exempts both for the same reason.
  await test('git and path dependencies are skipped before the gate', async () => {
    const { parseCargoLock } = require('../src/cargo-lock');
    const lock = path.join(tmp('lock'), 'Cargo.lock');
    fs.writeFileSync(lock, [
      '[[package]]\nname = "fresh"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
      '[[package]]\nname = "from-git"\nversion = "0.1.0"\nsource = "git+https://github.com/acme/g?rev=abc#abc"\n',
      '[[package]]\nname = "local-crate"\nversion = "0.1.0"\n',
    ].join('\n'));
    assert.deepStrictEqual(parseCargoLock(lock).map((p) => p.name), ['fresh']);
    const r = await runScan({ lockPath: lock, db: createMemoryStore(), log: () => {}, publishAge: gate() });
    assert.deepStrictEqual(r.results.map((x) => x.name), ['fresh']);
    assert.strictEqual(r.publishAge.gatedCount, 1);
  });

  // The re-check owns time-varying registry state, so it owns the age too: a
  // pin that has since aged past the threshold must stop being reported.
  await test('the 24h re-check recomputes the gate and clears an aged-out pin', async () => {
    const { openDb } = require('../src/db');
    const dbPath = path.join(tmp('rdb'), 'w.db');
    const db = openDb(dbPath);
    const pkg = [{ name: 'fresh', version: '1.2.3' }];

    const first = await runScan({ packages: pkg, db, log: () => {}, publishAge: gate() });
    assert.strictEqual(first.results[0].status, 'SUSPICIOUS', JSON.stringify(first.results[0]));
    assert.strictEqual(db.getStoredStatus('fresh', '1.2.3').status, 'SUSPICIOUS');

    // Same pin, same store, now with a threshold it has cleared. Backdate the
    // row so it is unambiguously due: `recheckMaxAgeMs: 0` puts the cutoff at
    // Date.now(), which a same-millisecond second run would tie with and skip.
    staleAll(db);
    const later = await runScan({
      packages: pkg, db, log: () => {},
      publishAge: { raw: '1 second', ms: 1000, excludes: [] },
    });
    assert.strictEqual(later.rechecked.length, 1, JSON.stringify(later.rechecked));
    assert.strictEqual(later.rechecked[0].status, 'CLEAN', JSON.stringify(later.rechecked[0]));
    assert.strictEqual(db.getStoredStatus('fresh', '1.2.3').status, 'CLEAN');
    assert.strictEqual(later.publishAge.gatedCount, 0);
    assert.strictEqual(later.publishAge.clearedCount, 1, JSON.stringify(later.publishAge));
    db.close();
  });

  await test('a package first scanned without the gate is picked up by the re-check', async () => {
    const { openDb } = require('../src/db');
    const db = openDb(path.join(tmp('rdb2'), 'w.db'));
    const pkg = [{ name: 'fresh', version: '1.2.3' }];

    const before = await runScan({ packages: pkg, db, log: () => {} });
    assert.strictEqual(before.results[0].status, 'CLEAN');

    staleAll(db);
    const after = await runScan({ packages: pkg, db, log: () => {}, publishAge: gate() });
    assert.strictEqual(after.results.length, 0, 'pass 1 skips an already-checked pin');
    assert.strictEqual(after.rechecked.length, 1, JSON.stringify(after.rechecked));
    assert.strictEqual(after.rechecked[0].status, 'SUSPICIOUS', JSON.stringify(after.rechecked));
    assert.strictEqual(after.publishAge.gatedCount, 1);
    assert.deepStrictEqual(after.suspicious.map((x) => x.name), ['fresh']);
    db.close();
  });

  // --- CLI ------------------------------------------------------------------
  const { spawn } = require('child_process');
  const bin = path.join(__dirname, '..', 'bin', 'cargo-witness.js');
  const runCli = (argv) => new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...argv], { env: process.env });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  const CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index';
  const lockFor = (entries) => {
    const p = path.join(tmp('lock'), 'Cargo.lock');
    fs.writeFileSync(p, entries.map(([n, v]) =>
      `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = "${CRATES_IO}"\n`).join('\n'));
    return p;
  };
  const tmpDb = () => path.join(tmp('db'), 'w.db');
  const freshLock = lockFor([['fresh', '1.2.3']]);
  const boundaryLock = lockFor([['boundary', '1.0.0']]);

  await test('CLI: --min-publish-age exits 1 on the fresh pin, 0 on the boundary pin', async () => {
    const a = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(), '--min-publish-age', '24 hours']);
    assert.strictEqual(a.code, 1, `exit ${a.code}\n${a.stdout}\n${a.stderr}`);
    const out = plain(a.stdout);
    assert.ok(out.includes('PUBLISH_AGE (1)'), out);
    assert.ok(/fresh@1\.2\.3\s+[\dhms ]+ old\s+clears /.test(out), out);
    assert.ok(out.includes(`threshold 24 hours (${KEY})`), out);
    assert.ok(out.split('\n').every((l) => l.length <= 80), 'output must fit 80 columns');

    const b = await runCli(['--scan', '--lock', boundaryLock, '--db', tmpDb(), '--min-publish-age', '24 hours']);
    assert.strictEqual(b.code, 0, `exit ${b.code}\n${b.stdout}\n${b.stderr}`);
  });

  await test('CLI: the same lockfile without the flag exits 0 and says nothing about age', async () => {
    const r = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb()]);
    assert.strictEqual(r.code, 0, `exit ${r.code}\n${r.stdout}`);
    assert.ok(!r.stdout.includes('PUBLISH_AGE'), r.stdout);
    assert.ok(!r.stdout.includes('publish age'), r.stdout);
  });

  await test('CLI: --min-publish-age with no value is an error, not a silent no-op', async () => {
    const r = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(), '--min-publish-age']);
    assert.strictEqual(r.code, 2, `exit ${r.code}\n${r.stdout}\n${r.stderr}`);
    assert.ok(r.stderr.includes('--min-publish-age'), r.stderr);
  });

  await test('CLI: --min-publish-age-exclude with no value is an error', async () => {
    const r = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(),
      '--min-publish-age', '24 hours', '--min-publish-age-exclude']);
    assert.strictEqual(r.code, 2, `exit ${r.code}: ${r.stdout} ${r.stderr}`);
    assert.ok(r.stderr.includes('--min-publish-age-exclude'), r.stderr);
  });

  await test('CLI: --cargo-config with no value is a clean error', async () => {
    const r = await runCli(['--write-cargo-config', '--min-publish-age', '7 days', '--cargo-config']);
    assert.strictEqual(r.code, 2, `exit ${r.code}\n${r.stdout}\n${r.stderr}`);
    assert.ok(r.stderr.includes('needs a path'), r.stderr);
    assert.ok(!/must be of type|TypeError/.test(r.stderr), r.stderr);
  });

  await test('CLI: an unparseable duration exits 2 and names the units', async () => {
    const r = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(), '--min-publish-age', '1 fortnight']);
    assert.strictEqual(r.code, 2, `exit ${r.code}\n${r.stdout}\n${r.stderr}`);
    assert.ok(r.stderr.includes('seconds, minutes, hours, days, weeks or months'), r.stderr);
    assert.ok(!r.stderr.includes('at Object'), 'no stack trace');
  });

  await test('CLI: --json carries a per-package publishAge and a top-level threshold', async () => {
    const lock = lockFor([['fresh', '1.2.3'], ['boundary', '1.0.0'], ['notime', '1.0.0']]);
    const r = await runCli(['--scan', '--lock', lock, '--db', tmpDb(), '--json', '-q',
      '--min-publish-age', '24 hours']);
    assert.strictEqual(r.code, 1);
    const j = JSON.parse(r.stdout);
    assert.strictEqual(j.publishAge.threshold, '24 hours');
    assert.strictEqual(j.publishAge.thresholdMs, DAY);
    assert.strictEqual(j.publishAge.key, KEY);
    const states = Object.fromEntries(j.results.map((x) => [x.name, x.publishAge.state]));
    assert.deepStrictEqual(states, { fresh: 'gated', boundary: 'cleared', notime: 'unchecked' });
    assert.ok(j.results.find((x) => x.name === 'fresh').publishAge.clearsAt.endsWith('Z'));
  });

  await test('CLI: --json without the flag has no publishAge key at all', async () => {
    const r = await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(), '--json', '-q']);
    const j = JSON.parse(r.stdout);
    assert.ok(!('publishAge' in j), JSON.stringify(Object.keys(j)));
    assert.ok(j.results.every((x) => !('publishAge' in x)));
  });

  await test('CLI: --sarif writes the PUBLISH_AGE rule at warning', async () => {
    const out = path.join(tmp('sarif'), 'out.sarif');
    await runCli(['--scan', '--lock', freshLock, '--db', tmpDb(), '-q',
      '--min-publish-age', '24 hours', '--sarif', out]);
    const sarif = JSON.parse(fs.readFileSync(out, 'utf8'));
    const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'PUBLISH_AGE');
    assert.ok(rule);
    assert.strictEqual(rule.defaultConfiguration.level, 'warning');
    assert.ok(sarif.runs[0].results.some((r) => r.ruleId === 'PUBLISH_AGE' && r.level === 'warning'));
  });

  await test('CLI: --diff explains a gated, a cleared, an unchecked and an exempt version', async () => {
    const g = await runCli(['--diff', 'fresh', '1.2.3', '--min-publish-age', '24 hours']);
    const gp = plain(g.stdout);
    assert.ok(gp.includes('publish age: GATED'), gp);
    assert.ok(gp.includes('clears '), gp);
    assert.ok(gp.includes(`threshold 24 hours (${KEY})`), gp);

    const c = await runCli(['--diff', 'boundary', '1.0.0', '--min-publish-age', '24 hours']);
    assert.ok(plain(c.stdout).includes('publish age: not gated'), c.stdout);

    const u = await runCli(['--diff', 'notime', '1.0.0', '--min-publish-age', '24 hours']);
    assert.ok(plain(u.stdout).includes('publish age: unchecked'), u.stdout);

    const x = await runCli(['--diff', 'fresh', '1.2.3', '--min-publish-age', '24 hours',
      '--min-publish-age-exclude', 'fresh']);
    assert.ok(x.stdout.includes('exempt via --min-publish-age-exclude'), x.stdout);

    const off = await runCli(['--diff', 'fresh', '1.2.3']);
    assert.ok(!off.stdout.includes('publish age'), off.stdout);
  });

  await test('CLI: --write-cargo-config reports the change and the toolchain honestly', async () => {
    const target = path.join(tmp('wcc'), '.cargo', 'config.toml');
    const r = await runCli(['--write-cargo-config', '--min-publish-age', '7 days',
      '--cargo-config', target, '--min-publish-age-exclude', 'internal@1.0.0']);
    assert.strictEqual(r.code, 0, `exit ${r.code}\n${r.stdout}\n${r.stderr}`);
    assert.ok(r.stdout.includes('does not exist yet'), r.stdout);
    assert.ok(r.stdout.includes(`${KEY} = "7 days"`), r.stdout);
    assert.ok(/enforces these keys|Could not read the installed cargo/.test(r.stdout), r.stdout);
    assert.ok(r.stdout.includes('rust-lang/cargo#17335'), r.stdout);
    assert.ok(r.stdout.includes('already recorded in Cargo.lock'), r.stdout);

    const back = readCargoConfig(target);
    assert.strictEqual(back.value, '7 days');
    assert.deepStrictEqual(back.excludes, ['internal@1.0.0']);

    // Re-running with a different value must say what it is replacing.
    const again = await runCli(['--write-cargo-config', '--min-publish-age', '14 days',
      '--cargo-config', target]);
    assert.ok(again.stdout.includes('"7 days" -> "14 days"'), again.stdout);
    assert.strictEqual(readCargoConfig(target).value, '14 days');
  });

  await test('CLI: --write-cargo-config warns when the resolver gate is set to allow', async () => {
    const target = path.join(tmp('wcc3'), 'config.toml');
    fs.writeFileSync(target, '[resolver]\nincompatible-publish-age = "allow"\n');
    const r = await runCli(['--write-cargo-config', '--min-publish-age', '7 days',
      '--cargo-config', target]);
    assert.strictEqual(r.code, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes('incompatible-publish-age = "allow"'), r.stdout);
    assert.ok(r.stdout.includes('Left untouched'), r.stdout);
    assert.ok(fs.readFileSync(target, 'utf8').includes('incompatible-publish-age = "allow"'));
  });

  await test('CLI: --write-cargo-config without a policy exits 2', async () => {
    const r = await runCli(['--write-cargo-config', '--cargo-config',
      path.join(tmp('wcc2'), 'config.toml')]);
    assert.strictEqual(r.code, 2, r.stdout + r.stderr);
    assert.ok(r.stderr.includes('--min-publish-age'), r.stderr);
  });

  server.close();
}

main();
