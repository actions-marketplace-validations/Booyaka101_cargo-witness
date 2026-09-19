'use strict';
/**
 * STEP 9 — GitHub Action entry point (CI mode).
 *
 * Reads inputs from the standard Actions env vars, runs the CI scan, writes a
 * job summary + step outputs, and exits non-zero if any newly-added crate is
 * SUSPICIOUS so the workflow fails.
 *
 * Bundled to dist/action.js via `npm run build:action` (@vercel/ncc), which also
 * vendors the native better-sqlite3 binary. Logic lives here so it stays testable.
 */
const fs = require('fs');
const { runCi } = require('./ci');
const { createMemoryStore } = require('./store');
const { parseDuration, DurationError, isAgeOnly } = require('./publish-age');

function getInput(name, fallback) {
  const key = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const v = process.env[key];
  return v !== undefined && v !== '' ? v : fallback;
}

/** Append to a GITHUB_* file env target (GITHUB_OUTPUT / GITHUB_STEP_SUMMARY). */
function appendEnvFile(envVar, text) {
  const file = process.env[envVar];
  if (!file) return;
  try {
    fs.appendFileSync(file, text);
  } catch {
    /* non-fatal */
  }
}

function writeSummary(report) {
  const lines = [];
  lines.push('## cargo-witness\n');
  lines.push(`Lockfile: \`${report.lockPath}\`  •  Added packages: **${report.addedPackages.length}**  •  Suspicious: **${report.suspiciousCount}**\n`);
  if (report.suspiciousCount > 0) {
    lines.push('\n### ⚠️ Suspicious packages\n');
    lines.push('| Package | Version | Flags |\n|---|---|---|\n');
    for (const s of report.suspicious) {
      const flags = (s.flags || [])
        .map((f) => (typeof f === 'string' ? f : `${f.flag}${f.file ? ` (${f.file})` : ''}`))
        .join(', ');
      lines.push(`| \`${s.name}\` | ${s.version} | ${flags} |\n`);
    }
    for (const s of report.suspicious) {
      for (const f of s.flags || []) {
        if (typeof f === 'object' && f.detail) lines.push(`\n**\`${s.name}@${s.version}\`** ${f.detail}\n`);
      }
    }
    // An age-only run has found no divergence and must not claim it has.
    lines.push(isAgeOnly(report.suspicious)
      ? '\nNothing here says these crates are malicious. They are newer than the configured minimum publish age, so nobody has had time to look yet. **Wait, pin an older version, or exempt them.**\n'
      : '\nThese crates are a supply-chain risk: a published artifact diverging from its git source, or a version crates.io no longer serves. **Do not build until reviewed.**\n');
  } else if (report.addedPackages.length === 0) {
    lines.push('\nNo dependency changes to check. ✅\n');
  } else {
    lines.push('\nAll newly-added dependencies match their git source. ✅\n');
  }
  appendEnvFile('GITHUB_STEP_SUMMARY', lines.join(''));
}

async function main() {
  const lockPath = getInput('cargo-lock', 'Cargo.lock');
  const token = getInput('github-token', process.env.GITHUB_TOKEN || '');
  if (token) process.env.GITHUB_TOKEN = token;
  const sarif = getInput('sarif', '');
  const failOn = getInput('fail-on', 'medium');
  const configPath = getInput('config', '') || undefined;

  // Off unless the workflow asks for it, so an upgrade never changes a verdict.
  const minAge = getInput('min-publish-age', '');
  let publishAge = null;
  if (minAge) {
    let d;
    try {
      d = parseDuration(minAge);
    } catch (e) {
      if (!(e instanceof DurationError)) throw e;
      console.log(`::error title=cargo-witness::${e.message}`);
      process.exit(2);
    }
    const excludes = getInput('min-publish-age-exclude', '')
      .split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
    publishAge = { raw: d.raw, ms: d.ms, excludes };
  }

  // Ephemeral runner → in-memory store; keeps the bundled action native-free
  // (no platform-specific better-sqlite3 binary committed to dist/).
  const { exitCode, report } = await runCi(lockPath, {
    store: createMemoryStore(),
    sarif: sarif || undefined,
    failOn,
    configPath,
    publishAge,
  });

  if (sarif) console.log(`cargo-witness: SARIF written to ${sarif}`);

  // Step outputs for downstream steps.
  appendEnvFile('GITHUB_OUTPUT', `suspicious-count=${report.suspiciousCount}\n`);
  appendEnvFile('GITHUB_OUTPUT', `suspicious=${JSON.stringify(report.suspicious)}\n`);

  writeSummary(report);

  // Inline error annotations.
  if (report.suspiciousCount > 0) {
    for (const s of report.suspicious) {
      const flags = (s.flags || [])
        .map((f) => (typeof f === 'string' ? f : f.flag))
        .join(', ');
      const detail = (s.flags || []).map((f) => (typeof f === 'object' && f.detail) || '').find(Boolean);
      console.log(`::error title=cargo-witness::${s.name}@${s.version}: ${flags}${detail ? ` — ${detail}` : ''}`);
    }
  }
  process.exit(exitCode);
}

main().catch((e) => {
  console.log(`::error title=cargo-witness::${e.message}`);
  process.exit(2);
});
