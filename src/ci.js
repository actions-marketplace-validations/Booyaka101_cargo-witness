'use strict';
const fs = require('fs');
const cp = require('child_process');
const { runScan } = require('./scanner');
const { parseCargoLock, isCratesIoSource } = require('./cargo-lock');
const { loadAllowlist } = require('./allowlist');
const { toSarif } = require('./sarif');
const { maxSeverity, atLeast } = require('./severity');

/**
 * STEP 8 (--ci) — CI mode.
 *
 * Uses `git diff HEAD~1 -- {lockPath}` to find newly ADDED packages (added
 * lines beginning with `name = "..."`), scans only those, prints a JSON report
 * to stdout, and exits 1 if any are SUSPICIOUS.
 *
 * @returns {Promise<{exitCode:number, report:object}>}
 */
async function runCi(lockPath = 'Cargo.lock', {
  concurrency = 5, store, sarif, configPath, failOn = 'medium', recheck = true,
  publishAge = null,
} = {}) {
  // The lockfile diff yields only name+version, so carry each package's
  // `source` over from the lockfile itself: without it an added alternate-
  // registry crate would be probed against crates.io, where a 404 means
  // nothing.
  const added = withLockfileSource(diffAddedPackages(lockPath), lockPath);

  // The store is injected by the caller: the CLI passes a persistent SQLite
  // store; the GitHub Action passes a pure-JS in-memory store so its bundle
  // carries no platform-specific native binary. Default to memory.
  const db = store || require('./store').createMemoryStore();
  const allow = loadAllowlist(configPath);

  // Added packages already recorded in the store keep their stored verdict —
  // a re-run must not silently pass a package we already flagged.
  const known = [];
  for (const p of added) {
    const s = db.getStoredStatus(p.name, p.version);
    if (s) known.push({ name: p.name, version: p.version, ...s });
  }

  // Pass ALL added packages: runScan skips already-recorded ones in its scan
  // pass but may refresh their registry state in the re-check pass (persistent
  // store only; the Action's fresh in-memory store has nothing due).
  const { results, rechecked, suppressedCount, publishAge: publishAgeSummary } = await runScan({
    lockPath,
    packages: added,
    db,
    concurrency,
    allowRules: allow.rules,
    log: (m) => process.stderr.write(m + '\n'),
    recheck,
    publishAge,
  });

  // A re-check may have updated a known package's verdict (e.g. its version
  // was deleted from crates.io since we cleared it) — prefer the fresh state.
  const refreshed = new Map((rechecked || []).map((r) => [`${r.name}@${r.version}`, r]));
  const scanned = [
    ...known.map((k) => {
      const r = refreshed.get(`${k.name}@${k.version}`);
      return r
        ? { name: k.name, version: k.version, status: r.status, flags: r.flags || [] }
        : { name: k.name, version: k.version, status: k.status, flags: k.flags };
    }),
    ...results.map((r) => ({ name: r.name, version: r.version, status: r.status, flags: r.flags || [] })),
  ];

  const suspicious = scanned
    .filter((s) => s.status === 'SUSPICIOUS')
    .map((s) => ({ name: s.name, version: s.version, flags: s.flags }));

  // Worst severity across findings, gated by fail-on.
  const worst = suspicious
    .map((p) => maxSeverity(p.flags))
    .reduce((a, b) => (atLeast(b, a || 'info') ? b : a), null);
  const gated = worst && atLeast(worst, failOn);

  const report = {
    lockPath,
    addedPackages: added,
    scanned,
    suspicious,
    suspiciousCount: suspicious.length,
    suppressedCount: suppressedCount || 0,
    worstSeverity: worst,
    failOn,
    ...(publishAgeSummary ? { publishAge: publishAgeSummary } : {}),
  };

  if (sarif) {
    fs.writeFileSync(sarif, JSON.stringify(toSarif(suspicious, lockPath), null, 2));
  }

  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  return { exitCode: gated ? 1 : 0, report };
}

/**
 * Tag each diffed package with whether the lockfile sources it from crates.io.
 * A package no longer present in the lockfile keeps `cratesIo` unset (unknown).
 */
function withLockfileSource(added, lockPath) {
  let sources;
  try {
    sources = new Map(
      parseCargoLock(lockPath, { withSource: true }).map((p) => [`${p.name}@${p.version}`, p.source])
    );
  } catch {
    return added; // unreadable lockfile: the scan itself will report it
  }
  return added.map((p) => {
    const source = sources.get(`${p.name}@${p.version}`);
    return source === undefined ? p : { ...p, source, cratesIo: isCratesIoSource(source) };
  });
}

/**
 * Parse newly added registry packages from the lockfile diff.
 * We look for added lines of the form `+name = "..."` and pair each with the
 * `+version = "..."` that follows it within the same added [[package]] block.
 */
function diffAddedPackages(lockPath) {
  let diff = '';
  try {
    diff = cp.execFileSync('git', ['diff', 'HEAD~1', '--', lockPath], {
      encoding: 'utf8',
    });
  } catch (e) {
    // No git history / not a repo / no previous commit → nothing added.
    process.stderr.write(
      `cargo-witness --ci: could not run git diff (${e.message.split('\n')[0]}). Treating as no changes.\n`
    );
    return [];
  }

  const added = [];
  const lines = diff.split(/\r?\n/);
  let pendingName = null;
  for (const line of lines) {
    if (!line.startsWith('+') || line.startsWith('+++')) {
      // A context/removed line ends any half-parsed package entry only if it
      // is a package boundary; otherwise keep pendingName so name/version that
      // straddle unchanged `source =` lines still pair up.
      continue;
    }
    const body = line.slice(1).trim();
    const nameM = body.match(/^name\s*=\s*"([^"]+)"/);
    if (nameM) {
      pendingName = nameM[1];
      continue;
    }
    const verM = body.match(/^version\s*=\s*"([^"]+)"/);
    if (verM && pendingName) {
      added.push({ name: pendingName, version: verM[1] });
      pendingName = null;
    }
  }

  return added;
}

module.exports = { runCi, diffAddedPackages };
