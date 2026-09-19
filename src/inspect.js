'use strict';
const fs = require('fs');
const path = require('path');
const { fetchCrate, fetchCrateMeta } = require('./fetcher');
const { fetchGitTree } = require('./git-tree');
const { diff, normalizeSource } = require('./differ');
const { diffManifests } = require('./manifest');
const { severityOf, isSuspicious } = require('./severity');
const { evaluatePublishAge, isExcluded, formatAge, formatStamp, KEY } = require('./publish-age');

const C = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
};

/**
 * `--diff <name> <version>` — human investigation view for one crate: resolve
 * the source commit, list which files diverge, and print a unified diff of any
 * modified Rust source (especially build.rs) so a human can judge the finding.
 *
 * With `publishAge` set (--min-publish-age) it also says, in one line, why the
 * version was or was not gated. Without it the output is unchanged.
 */
async function inspectDiff(name, version, { log = console.log, publishAge = null } = {}) {
  // A withdrawn version has no artifact to diff; explain the finding instead of
  // failing on the missing download.
  const meta = await fetchCrateMeta(name, version);
  if (meta.absent) {
    const flag = meta.crateExists ? 'VERSION_REMOVED' : 'CRATE_REMOVED';
    log(`${C.bold}cargo-witness --diff ${name}@${version}${C.reset}`);
    log(`${C.red}● ${flag}${C.reset}`);
    log(meta.crateExists
      ? `${C.dim}crates.io no longer serves this version; the crate exists but ${version} was removed\n` +
        'from the registry. There is no published artifact left to diff. A deleted version is how\n' +
        `crates.io responds to a malicious publish, so treat this as compromised until proven otherwise.${C.reset}`
      : `${C.dim}crates.io no longer serves this crate at all; both the version and the crate return 404,\n` +
        `so there is no published artifact to diff. If every crate reports this, suspect a proxy.${C.reset}`);
    log(`\n${C.dim}Check whether the artifact was already fetched and built locally:\n` +
      `  ls ~/.cargo/registry/cache/*/${name}-${version}.crate${C.reset}\n`);
    return { status: 'SUSPICIOUS', flags: [{ flag, file: null, severity: 'high' }] };
  }

  log(`${C.bold}cargo-witness --diff ${name}@${version}${C.reset}`);
  if (publishAge) printPublishAgeLine(name, version, meta, publishAge, log);

  const crate = await fetchCrate(name, version, { meta });
  try {
    const tp = crate.trustpub;
    const attestedSha = tp && tp.sha ? tp.sha : undefined;
    const attestedRepo = tp && tp.provider === 'github' && tp.repository ? `https://github.com/${tp.repository}` : undefined;
    const vcsSha = crate.vcsInfo ? crate.vcsInfo.sha1 : undefined;

    const tree = await fetchGitTree(crate.repository, name, version, { vcsSha, attestedSha, attestedRepo });

    if (!tree.gitFiles) {
      log(`${C.yellow}No comparable source found (repository=${crate.repository || 'none'}). Nothing to diff.${C.reset}`);
      return { status: 'NO_GIT_TAG' };
    }
    const anchor =
      tree.refKind === 'attested' ? `attested commit ${short(tree.ref)} (OIDC)` :
      tree.refKind === 'vcs' ? `published commit ${short(tree.ref)} (.cargo_vcs_info.json)` :
      `tag ${tree.ref}`;
    log(`${C.dim}source: ${tree.host} ${tree.owner}/${tree.repo} @ ${anchor}${C.reset}\n`);

    const knownPrefix = crate.vcsInfo ? { knownPrefix: crate.vcsInfo.pathInVcs } : {};
    const result = diff(crate.crateFiles, tree.gitFiles, crate.prefix, knownPrefix);

    // Manifest lane: dependency names in the artifact's Cargo.toml vs git's.
    let manifest;
    if (result.status === 'NO_GIT_TAG') {
      manifest = { flags: [], skipped: result.note || 'crate could not be located in the git tree' };
    } else {
      try {
        const artifactToml = fs.readFileSync(
          path.join(crate.dir, `${name}-${version}`, 'Cargo.toml'), 'utf8');
        manifest = await diffManifests({
          name, artifactToml, gitFiles: tree.gitFiles, gitPrefix: result.gitPrefix,
          raw: (fp) => tree.provider.raw(tree.ref, fp),
        });
      } catch (e) {
        manifest = { flags: [], skipped: e.message };
      }
    }
    const flags = [...result.flags, ...manifest.flags];

    if (flags.length === 0 && (!result.contentSuspects || result.contentSuspects.length === 0)) {
      if (manifest.skipped) log(`${C.dim}manifest comparison skipped: ${manifest.skipped}${C.reset}`);
      log(`${C.green}No divergence: every published file matches the source.${C.reset}`);
      return { status: result.status };
    }

    // Absence-based flags.
    for (const f of flags) {
      const col = severityOf(f) === 'high' ? C.red : severityOf(f) === 'medium' ? C.yellow : C.cyan;
      log(`${col}● ${f.flag}${f.file ? ` ${f.file}` : ''}${C.reset}`);
    }
    if (manifest.skipped) {
      log(`${C.dim}manifest comparison skipped: ${manifest.skipped}${C.reset}`);
    } else if (manifest.flags.length > 0) {
      printDepSets(manifest, log);
    }

    // Content diffs for confirmed-different .rs files.
    for (const s of result.contentSuspects || []) {
      const localPath = path.join(crate.dir, `${name}-${version}`, s.rel);
      let local = '';
      try { local = fs.readFileSync(localPath, 'utf8'); } catch { continue; }
      const gitPath = result.gitPrefix ? `${result.gitPrefix}/${s.rel}` : s.rel;
      let remote = null;
      try { remote = await tree.provider.raw(tree.ref, gitPath); } catch { /* ignore */ }
      if (remote == null) continue;
      if (normalizeSource(remote) === normalizeSource(local)) continue; // benign (line endings)

      const flag = s.isBuildRs ? 'BUILD_RS_MODIFIED' : 'SOURCE_MODIFIED';
      log(`\n${C.bold}${s.isBuildRs ? C.red : C.yellow}▼ ${flag}: ${s.rel}${C.reset}`);
      log(`${C.dim}  (− source / + published)${C.reset}`);
      printUnifiedDiff(remote, local, log);
    }
    log('');
    return { status: isSuspicious(flags) ? 'SUSPICIOUS' : result.status, flags };
  } finally {
    crate.cleanup();
  }
}

/**
 * One line saying whether the publish-age gate fired on this version, and why.
 * The gate reads registry metadata only, so this is decided before any artifact
 * or git-side work and is printed whatever those lanes go on to do.
 */
function printPublishAgeLine(name, version, meta, publishAge, log) {
  const say = (verdict, why) => {
    log(`${C.dim}publish age:${C.reset} ${verdict} — ${why}`);
    log(`${C.dim}             threshold ${publishAge.raw} (${KEY})${C.reset}`);
  };

  if (isExcluded(publishAge.excludes, name, version)) {
    return say(`${C.green}not gated${C.reset}`, 'exempt via --min-publish-age-exclude');
  }
  const ev = evaluatePublishAge(meta.createdAt, publishAge.ms);
  if (ev.state === 'unchecked') {
    return say(`${C.yellow}unchecked${C.reset}`, `${ev.reason}; an unknown age is never gated`);
  }
  const age = `${formatAge(ev.ageMs)} old (published ${formatStamp(ev.publishedMs)})`;
  if (ev.state === 'cleared') {
    return say(`${C.green}not gated${C.reset}`, `${age}, past the threshold`);
  }
  return say(`${C.red}GATED${C.reset}`, `${age}, clears ${formatStamp(ev.clearsAtMs)}`);
}

/** Both dependency-name sets side by side, injected names marked in red. */
function printDepSets(manifest, log) {
  const gitSet = new Set(manifest.gitDeps || []);
  const injected = new Set(manifest.flags.map((f) => f.file));
  const all = [...new Set([...manifest.artifactDeps, ...gitSet])].sort();
  const w = Math.max(10, ...all.map((n) => n.length)) + 2;
  log(`\n${C.bold}▼ dependency names (published artifact vs git source)${C.reset}`);
  log(`${C.dim}  ${'ARTIFACT'.padEnd(w)}GIT${C.reset}`);
  for (const n of all) {
    const a = manifest.artifactDeps.includes(n) ? n : '—';
    const g = gitSet.has(n) ? n : '—';
    const col = injected.has(n) ? C.red : C.dim;
    log(`${col}  ${a.padEnd(w)}${g}${injected.has(n) ? '   ← declared only in the artifact' : ''}${C.reset}`);
  }
}

function short(sha) {
  return String(sha).slice(0, 10);
}

/** Minimal LCS-based line diff. `a`=old (git), `b`=new (published). */
function diffOps(aStr, bStr) {
  const a = String(aStr).replace(/\r\n/g, '\n').split('\n');
  const b = String(bStr).replace(/\r\n/g, '\n').split('\n');
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);

  const ops = [];
  let i = 0, j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) { ops.push([' ', a[i]]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push(['-', a[i]]); i++; }
    else { ops.push(['+', b[j]]); j++; }
  }
  while (i < m) ops.push(['-', a[i++]]);
  while (j < n) ops.push(['+', b[j++]]);
  return ops;
}

/** Render a unified diff (hunks with context). */
function printUnifiedDiff(aStr, bStr, log, { maxLines = 4000, context = 3 } = {}) {
  const alen = String(aStr).split('\n').length, blen = String(bStr).split('\n').length;
  if (alen > maxLines || blen > maxLines) {
    log(`${C.dim}  (files too large to inline-diff: ${alen} vs ${blen} lines)${C.reset}`);
    return;
  }
  const ops = diffOps(aStr, bStr);

  // Render only hunks around changes (with `context` unchanged lines).
  const keep = new Array(ops.length).fill(false);
  ops.forEach((o, k) => {
    if (o[0] !== ' ') for (let d = -context; d <= context; d++) if (ops[k + d]) keep[k + d] = true;
  });
  let lastPrinted = -2;
  ops.forEach((o, k) => {
    if (!keep[k]) return;
    if (k > lastPrinted + 1) log(`${C.dim}  …${C.reset}`);
    const col = o[0] === '+' ? C.green : o[0] === '-' ? C.red : C.dim;
    log(`${col}  ${o[0]} ${o[1]}${C.reset}`);
    lastPrinted = k;
  });
}

module.exports = { inspectDiff, diffOps };
