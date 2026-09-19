'use strict';
const { severityOf, maxSeverity } = require('./severity');
const { formatAge, formatStamp, isAgeOnly } = require('./publish-age');
const { wrapText } = require('./util');

const C = {
  red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
};

const SEV_COLOR = { high: C.red, medium: C.yellow, info: C.cyan };

/**
 * STEP 8 (--report) — print SUSPICIOUS packages from SQLite, coloured by
 * severity. With {json:true} print machine-readable JSON instead.
 */
function printReport(store, { json = false } = {}) {
  const rows = store.getSuspicious();

  if (json) {
    process.stdout.write(
      JSON.stringify(
        rows.map((r) => ({
          name: r.name, version: r.version, status: r.status,
          severity: maxSeverity(r.flags), checked_at: r.checked_at, flags: r.flags,
        })),
        null, 2
      ) + '\n'
    );
    return rows;
  }

  console.log(`${C.bold}cargo-witness — SUSPICIOUS packages${C.reset}\n`);

  if (rows.length === 0) {
    console.log(`${C.dim}  (none) — no suspicious crates recorded.${C.reset}\n`);
    return rows;
  }

  const header = pad('SEV', 8) + pad('PACKAGE', 30) + pad('VERSION', 14) + 'FLAGS';
  console.log(`${C.bold}${header}${C.reset}`);
  console.log(`${C.dim}${'-'.repeat(header.length + 8)}${C.reset}`);

  for (const r of rows) {
    const sev = maxSeverity(r.flags) || 'medium';
    const color = SEV_COLOR[sev] || C.red;
    const flags = (r.flags || [])
      .map((f) => {
        const name = typeof f === 'string' ? f : f.flag;
        const file = typeof f === 'string' ? null : f.file;
        return `${name}${file ? `(${file})` : ''}`;
      })
      .join(', ');
    const line = pad(sev.toUpperCase(), 8) + pad(r.name, 30) + pad(r.version, 14) + flags;
    console.log(`${color}${line}${C.reset}`);
  }
  console.log('');
  // An age-only report has found no divergence and must not read as if it had.
  if (isAgeOnly(rows)) {
    console.log(`${C.bold}${C.yellow}${rows.length} package(s) newer than the configured `
      + `minimum publish age.${C.reset}`);
    console.log(`${C.dim}Nothing here says they are malicious. Nobody has had time to `
      + `look yet.${C.reset}\n`);
    return rows;
  }
  const high = rows.filter((r) => maxSeverity(r.flags) === 'high').length;
  console.log(
    `${C.bold}${C.red}${rows.length} suspicious package(s)` +
    (high ? ` (${high} high severity)` : '') +
    `. Investigate before building.${C.reset}\n`
  );
  return rows;
}

/**
 * The PUBLISH_AGE section of a `--scan`, printed only when --min-publish-age
 * was passed. One entry per gated crate, and where a crate also trips a
 * high/medium flag from another lane that is said on the same entry: young AND
 * diverging is the combination worth waking someone for, not two findings.
 *
 * @param {object} summary  runScan().publishAge
 * @param {{log?:Function}} [opts]
 */
function printPublishAge(summary, { log = console.log } = {}) {
  if (!summary) return;
  const { gated = [], unchecked = [], excluded = [] } = summary;
  if (gated.length === 0 && unchecked.length === 0 && excluded.length === 0) return;

  log('');
  if (gated.length > 0) {
    log(`${C.bold}${C.yellow}PUBLISH_AGE (${gated.length})${C.reset}`);
    log(`${C.dim}  threshold ${summary.threshold} (${summary.key})${C.reset}`);
    // Two spaces of indent, the label column, then a 38-column tail keeps the
    // entry inside 80. A label longer than the cap drops its tail onto the
    // detail line below rather than pushing it off the edge.
    const labels = gated.map((g) => `${g.name}@${g.version}`);
    const w = Math.min(40, Math.max(20, ...labels.map((l) => l.length)) + 2);
    gated.forEach((g, i) => {
      const worst = g.alsoFlagged.find((f) => f.severity === 'high') || g.alsoFlagged[0];
      const color = worst ? C.red : C.yellow;
      const tail = `${formatAge(g.ageMs).padStart(7)} old   clears ${formatStamp(g.clearsAtMs)}`;
      if (labels[i].length <= w) {
        log(`${color}  ${labels[i].padEnd(w)}${tail}${C.reset}`);
      } else {
        log(`${color}  ${labels[i]}${C.reset}`);
        log(`${color}    ${tail.trimStart()}${C.reset}`);
      }
      log(`${C.dim}    published ${formatStamp(g.publishedMs)}${C.reset}`);
      if (worst) {
        const others = g.alsoFlagged
          .map((f) => `${f.flag}${f.file ? `(${f.file})` : ''}`).join(', ');
        for (const line of wrapText(
          `and already flagged ${others} — a version this young that also diverges from ` +
          'its source is an active incident, not a cooldown question.', 72)) {
          log(`${C.red}    ${line}${C.reset}`);
        }
      }
    });

    const subject = gated.length === 1 ? 'what the crate does' : 'what these crates do';
    const hint = gated.length === 1
      ? `--min-publish-age-exclude ${gated[0].name}`
      : '--min-publish-age-exclude <name>';
    log('');
    for (const line of wrapText(
      `This says nothing about ${subject}. arrayref@0.3.10, internment@0.8.7 and ` +
      'append-only-vec@0.1.9 were each deleted within 107 minutes of publication. ' +
      `Wait, pin an older version, or exempt with ${hint}.`, 74)) {
      log(`${C.dim}  ${line}${C.reset}`);
    }
  }

  // Never blocked, always said out loud: a registry that publishes no time
  // (mirrors, vendored sources, alternate registries) is unchecked, not clean.
  if (unchecked.length > 0) {
    log('');
    log(`${C.dim}  ${unchecked.length} version(s) had no registry publish time — ` +
      `unchecked, not gated:${C.reset}`);
    for (const u of unchecked) log(`${C.dim}    ${u.name}@${u.version} — ${u.reason}${C.reset}`);
  }
  if (excluded.length > 0) {
    log(`${C.dim}  ${excluded.length} version(s) exempt from the gate: ` +
      `${excluded.map((e) => `${e.name}@${e.version}`).join(', ')}${C.reset}`);
  }
}

/** --history: recent scan runs. */
function printHistory(store, limit = 20) {
  const runs = store.getRuns(limit);
  console.log(`${C.bold}cargo-witness — recent runs${C.reset}\n`);
  if (runs.length === 0) {
    console.log(`${C.dim}  (no runs recorded yet)${C.reset}\n`);
    return runs;
  }
  console.log(`${C.bold}${pad('WHEN', 26) + pad('CHECKED', 10) + 'SUSPICIOUS'}${C.reset}`);
  for (const r of runs) {
    const when = new Date(r.run_at).toISOString();
    const sc = r.suspicious_count > 0 ? `${C.red}${r.suspicious_count}${C.reset}` : '0';
    console.log(pad(when, 26) + pad(String(r.new_count), 10) + sc);
  }
  console.log('');
  return runs;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s.slice(0, n - 1) + ' ' : s + ' '.repeat(n - s.length);
}

module.exports = { printReport, printHistory, printPublishAge };
