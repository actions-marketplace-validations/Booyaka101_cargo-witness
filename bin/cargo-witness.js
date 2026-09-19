#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const { openDb } = require('../src/db');
const { runScan } = require('../src/scanner');
const { printReport, printHistory, printPublishAge } = require('../src/report');
const { notifySuspicious } = require('../src/notifier');
const { runCi } = require('../src/ci');
const { inspectDiff } = require('../src/inspect');
const { loadAllowlist } = require('../src/allowlist');
const { toSarif } = require('../src/sarif');
const { maxSeverity, atLeast } = require('../src/severity');
const { parseDuration, DurationError, KEY } = require('../src/publish-age');
const {
  readCargoConfig, writeCargoConfig, cargoToolchain, RESOLVER_KEY,
} = require('../src/cargo-config');
const pkg = require('../package.json');

const CARGO_CONFIG_DEFAULT = path.join('.cargo', 'config.toml');
const NEWLINE = '\n';

function parseArgs(argv) {
  const args = {
    mode: null, lock: 'Cargo.lock', concurrency: 5, json: false, quiet: false,
    db: undefined, now: false, failOn: 'medium', sarif: undefined, config: undefined,
    recheck: true, minPublishAge: undefined, minPublishAgeExclude: [],
    cargoConfig: CARGO_CONFIG_DEFAULT,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--scan': args.mode = 'scan'; break;
      case '--daemon': args.mode = 'daemon'; break;
      case '--report': args.mode = 'report'; break;
      case '--history': args.mode = 'history'; break;
      case '--diff': args.mode = 'diff'; args.diffName = argv[++i]; args.diffVersion = argv[++i]; break;
      case '--ci': args.mode = 'ci'; break;
      case '--lock': args.lock = argv[++i]; break;
      case '--concurrency': args.concurrency = Math.max(1, parseInt(argv[++i], 10) || 5); break;
      case '--db': args.db = argv[++i]; break;
      case '--config': args.config = argv[++i]; break;
      case '--sarif': args.sarif = argv[++i]; break;
      case '--fail-on': args.failOn = String(argv[++i] || 'medium').toLowerCase(); break;
      case '--json': args.json = true; break;
      case '--quiet': case '-q': args.quiet = true; break;
      case '--no-recheck': args.recheck = false; break;
      case '--min-publish-age': args.minPublishAge = argv[++i] ?? ''; break;
      case '--min-publish-age-exclude': args.minPublishAgeExclude.push(argv[++i]); break;
      case '--write-cargo-config': args.mode = 'write-cargo-config'; break;
      case '--cargo-config': args.cargoConfig = argv[++i]; break;
      case '--now': args.now = true; break;
      case '--version': case '-V': args.mode = 'version'; break;
      case '--help': case '-h': args.mode = 'help'; break;
      default:
        if (a.startsWith('-')) { process.stderr.write(`Unknown option: ${a}\n`); args.mode = 'help'; }
    }
  }
  if (!['high', 'medium', 'info'].includes(args.failOn)) args.failOn = 'medium';
  return args;
}

const HELP = `cargo-witness v${pkg.version} — detect Rust supply-chain attacks by
diffing published crates against their git source.

Usage:
  cargo-witness --scan   [options]   One-time scan; exit non-zero if suspicious.
  cargo-witness --daemon [options]   Nightly scan at 03:00 (node-cron).
  cargo-witness --report [options]   Print SUSPICIOUS packages (severity table).
  cargo-witness --history            Print recent scan runs.
  cargo-witness --diff <name> <ver>  Show how a crate's artifact differs from source.
  cargo-witness --ci     [options]   CI: scan only newly-added packages,
                                     print JSON, exit 1 if any SUSPICIOUS.
  cargo-witness --write-cargo-config --min-publish-age <span>
                                     Write the policy into .cargo/config.toml.

Options:
  --lock <path>          Path to Cargo.lock (default: Cargo.lock)
  --concurrency <n>      Parallel crate checks (default: 5)
  --db <path>            SQLite DB path (default: ~/.cargo-witness/witness.db)
  --config <path>        Allowlist file (default: ./.cargo-witness.json)
  --fail-on <level>      Exit non-zero at/above severity: high|medium|info
                         (default: medium)
  --sarif <path>         Write a SARIF 2.1.0 report (for code scanning)
  --no-recheck           Skip the 24h registry metadata re-check of
                         already-cleared packages (yanked/removed state)
  --min-publish-age <span>
                         Gate lockfile pins younger than <span>. RFC 3923
                         grammar: N seconds|minutes|hours|days|weeks|months,
                         or "0" to disable. Off unless passed.
  --min-publish-age-exclude <name>
                         Exempt a crate from the gate; repeatable. Accepts
                         "name" or "name@version".
  --cargo-config <path>  Target for --write-cargo-config
                         (default: .cargo/config.toml)
  --json                 Machine-readable output (--scan / --report)
  --now                  (--daemon) run one scan immediately on startup
  --quiet, -q            Suppress per-crate progress lines
  --version, -V          Print version
  --help, -h             This help

Env:
  GITHUB_TOKEN             Raise GitHub API rate limit (60/hr -> 5000/hr).
  CARGO_WITNESS_NO_NOTIFY  Disable desktop notifications.
`;

function makeLog(args) {
  return args.quiet ? () => {} : (m) => console.log(m);
}

function writeSarif(sarifPath, suspicious, lockPath) {
  if (!sarifPath) return;
  fs.writeFileSync(sarifPath, JSON.stringify(toSarif(suspicious, lockPath), null, 2));
}

/**
 * `--write-cargo-config` — put the policy where cargo will read it.
 *
 * Writes `registry.global-min-publish-age`, the one key that carries this
 * threshold for cargo, and records the exemptions alongside it. RFC 3923
 * defers a per-package exclude list to future work and cargo ships no key for
 * one, so the exemptions go in as a marker comment cargo-witness reads back:
 * inventing a cargo key would make the file the tool just wrote a file cargo
 * complains about.
 *
 * @returns {number} exit code
 */
function writeCargoConfigMode(args) {
  const target = args.cargoConfig;
  if (!target) {
    process.stderr.write('cargo-witness: --cargo-config needs a path.' + NEWLINE);
    return 2;
  }
  const publishAge = resolvePublishAge(args);
  if (!publishAge) {
    process.stderr.write(
      'cargo-witness --write-cargo-config needs a policy to write: ' +
      'pass --min-publish-age <span> (e.g. --min-publish-age "7 days").' + NEWLINE);
    return 2;
  }

  let before;
  try {
    before = readCargoConfig(target);
  } catch (e) {
    process.stderr.write(`cargo-witness: cannot read ${target}: ${e.message}` + NEWLINE);
    return 2;
  }

  // Never overwrite in silence: say what the file held before it is changed.
  console.log(`cargo-witness --write-cargo-config -> ${target}`);
  if (!before.exists) console.log('  this file does not exist yet; it will be created.');
  else if (before.value === null) console.log(`  ${KEY} was not set in this file.`);
  else if (before.value === publishAge.raw) console.log(`  ${KEY} is already "${before.value}"; left at that value.`);
  else console.log(`  ${KEY}: "${before.value}" -> "${publishAge.raw}"`);
  if (before.excludes.length) console.log(`  previous exemptions: ${before.excludes.join(', ')}`);
  if (before.resolverMode === 'allow') {
    console.log(`  NOTE: this file sets resolver.${RESOLVER_KEY} = "allow", which turns`);
    console.log('  cargo\'s resolver gate off. The threshold below will be inert for cargo');
    console.log('  until you remove that or set it to "deny". cargo-witness reads the');
    console.log('  threshold regardless. Left untouched: it is your call, not this tool\'s.');
  }

  let res;
  try {
    res = writeCargoConfig(target, publishAge.raw, publishAge.excludes);
  } catch (e) {
    process.stderr.write(`cargo-witness: cannot write ${target}: ${e.message}` + NEWLINE);
    return 2;
  }

  console.log(`  ${res.created ? 'created' : 'updated'}: ${KEY} = "${res.value}"`
    + (res.dotted ? ' (kept in dotted form, as this file already uses it)' : ''));
  console.log(`  exemptions: ${publishAge.excludes.length ? publishAge.excludes.join(', ') : '(none)'}`);
  if (publishAge.excludes.length) {
    console.log('  Exemptions are written as a cargo-witness marker comment: RFC 3923');
    console.log('  defers an exclude list, so cargo has no key for one. cargo reads the');
    console.log('  threshold; cargo-witness reads both.');
  }

  const cargo = cargoToolchain();
  console.log('');
  if (cargo.enforces === true) {
    console.log(`  Your cargo is ${cargo.version}, which enforces these keys ` +
      '(stabilized in rust-lang/cargo#17335, Rust 1.100).');
  } else if (cargo.enforces === false) {
    console.log(`  Your cargo is ${cargo.version}. cargo enforces these keys from Rust 1.100`);
    console.log('  (stabilized in rust-lang/cargo#17335; nightly -Zmin-publish-age before');
    console.log('  that), so on this toolchain the file is inert until you upgrade.');
  } else {
    console.log(`  Could not read the installed cargo (${cargo.error}). cargo enforces these`);
    console.log('  keys from Rust 1.100 (rust-lang/cargo#17335); on anything older the file');
    console.log('  sits inert until you upgrade.');
  }
  console.log('  Either way cargo only gates RESOLUTION, and its own rule exempts versions');
  console.log('  already recorded in Cargo.lock. Run');
  console.log(`    cargo-witness --scan --min-publish-age "${publishAge.raw}"`);
  console.log('  to audit the pinned half.');
  return 0;
}

/** Exit code from findings given the fail-on threshold. */
function gateExit(suspicious, failOn) {
  const worst = suspicious
    .map((p) => maxSeverity(p.flags))
    .reduce((a, b) => (atLeast(b, a || 'info') ? b : a), null);
  return worst && atLeast(worst, failOn) ? 1 : 0;
}

/**
 * Resolve --min-publish-age into the shape runScan/inspectDiff want, or null
 * when the flag is absent. An unreadable duration is a usage error (exit 2),
 * never a silently-disabled gate.
 */
function resolvePublishAge(args) {
  if (args.minPublishAge === undefined) return null;
  let d;
  try {
    d = parseDuration(args.minPublishAge);
  } catch (e) {
    if (!(e instanceof DurationError)) throw e;
    process.stderr.write(`cargo-witness: ${e.message}\n`);
    process.exit(2);
  }
  const excludes = args.minPublishAgeExclude;
  if (excludes.some((e) => !e)) {
    process.stderr.write(
      'cargo-witness: --min-publish-age-exclude needs a crate name '
      + '("name" or "name@version").' + NEWLINE);
    process.exit(2);
  }
  return { raw: d.raw, ms: d.ms, excludes };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.mode === 'version') { process.stdout.write(`${pkg.version}\n`); return; }
  if (!args.mode || args.mode === 'help') {
    process.stdout.write(HELP);
    process.exit(args.mode ? 0 : 1);
  }

  if (args.mode === 'write-cargo-config') { process.exit(writeCargoConfigMode(args)); }

  if (args.mode === 'report') { printReport(openDb(args.db), { json: args.json }); return; }
  if (args.mode === 'history') { printHistory(openDb(args.db)); return; }

  if (args.mode === 'diff') {
    if (!args.diffName || !args.diffVersion) {
      process.stderr.write('Usage: cargo-witness --diff <name> <version>\n');
      process.exit(2);
    }
    await inspectDiff(args.diffName, args.diffVersion, { publishAge: resolvePublishAge(args) });
    return;
  }

  if (args.mode === 'ci') {
    const { exitCode } = await runCi(args.lock, {
      concurrency: args.concurrency, store: openDb(args.db), sarif: args.sarif,
      configPath: args.config, failOn: args.failOn, recheck: args.recheck,
      publishAge: resolvePublishAge(args),
    });
    process.exit(exitCode);
  }

  if (args.mode === 'scan') {
    const db = openDb(args.db);
    const allow = loadAllowlist(args.config);
    if (allow.path && !args.quiet) console.log(`Using allowlist: ${allow.path}`);
    const { newCount, suspicious, results, rechecked, suppressedCount, publishAge } = await runScan({
      lockPath: args.lock, db, concurrency: args.concurrency,
      allowRules: allow.rules, log: makeLog(args), recheck: args.recheck,
      publishAge: resolvePublishAge(args),
    });
    notifySuspicious(suspicious);
    writeSarif(args.sarif, suspicious, args.lock);

    if (args.json) {
      process.stdout.write(JSON.stringify({
        newCount, suspiciousCount: suspicious.length, suppressedCount,
        recheckedCount: (rechecked || []).length, suspicious,
        ...(publishAge ? { publishAge } : {}),
        results: results.map((r) => ({
          name: r.name, version: r.version, status: r.status, flags: r.flags || [],
          ...(r.manifestSkipped ? { manifestSkipped: r.manifestSkipped } : {}),
          ...(r.publishAge ? { publishAge: r.publishAge } : {}),
        })),
        rechecked: (rechecked || []).map((r) => ({ name: r.name, version: r.version, status: r.status, flags: r.flags || [] })),
      }, null, 2) + '\n');
    } else {
      if (!args.quiet) printPublishAge(publishAge);
      console.log('');
      console.log(`Done. ${newCount} package(s) checked, ${suspicious.length} SUSPICIOUS` +
        (suppressedCount ? `, ${suppressedCount} suppressed` : '') +
        ((rechecked || []).length ? `, ${rechecked.length} re-checked` : '') + '.');
      if (args.sarif) console.log(`SARIF written to ${args.sarif}`);
      if (suspicious.length > 0) console.log("Run 'cargo-witness --report' for details.");
    }
    process.exit(gateExit(suspicious, args.failOn));
  }

  if (args.mode === 'daemon') {
    const log = makeLog(args);
    const allow = loadAllowlist(args.config);
    const doScan = async () => {
      const stamp = new Date().toISOString();
      console.log(`[${stamp}] cargo-witness daemon: starting scan`);
      try {
        const db = openDb(args.db);
        const { newCount, suspicious, publishAge } = await runScan({
          lockPath: args.lock, db, concurrency: args.concurrency, allowRules: allow.rules, log,
          recheck: args.recheck, publishAge: resolvePublishAge(args),
        });
        if (!args.quiet) printPublishAge(publishAge);
        notifySuspicious(suspicious);
        console.log(`[${new Date().toISOString()}] scan complete: ${newCount} checked, ${suspicious.length} SUSPICIOUS`);
      } catch (e) {
        console.error(`daemon scan error: ${e.message}`);
      }
      console.log('cargo-witness daemon: next scan at 03:00');
    };

    console.log('cargo-witness daemon: next scan at 03:00');
    const task = cron.schedule('0 3 * * *', doScan);
    task.start();

    const shutdown = () => {
      console.log('\ncargo-witness daemon: shutting down');
      try { task.stop(); } catch { /* ignore */ }
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    if (args.now) await doScan();
    process.stdin.resume();
    return;
  }
}

main().catch((e) => {
  console.error('cargo-witness fatal:', e.message);
  process.exit(2);
});
