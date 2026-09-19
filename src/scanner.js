'use strict';
const fs = require('fs');
const path = require('path');
const { parseCargoLock, isCratesIoSource } = require('./cargo-lock');
const { fetchCrate, fetchCrateMeta } = require('./fetcher');
const { fetchGitTree } = require('./git-tree');
const { diff, normalizeSource, pushFlag } = require('./differ');
const { diffManifests } = require('./manifest');
const { isSuspicious, severityOf } = require('./severity');
const { applyAllowlist } = require('./allowlist');
const { evaluatePublishAge, isExcluded, formatAge, formatStamp, KEY } = require('./publish-age');
const { pool, wrapText } = require('./util');

const RECHECK_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// Flags the metadata re-check owns: recomputed from current registry state on
// every re-check; everything else (the git-diff verdict) is carried over.
const META_FLAGS = new Set(['YANKED', 'VERSION_REMOVED', 'CRATE_REMOVED', 'PUBLISH_AGE']);

/**
 * Core scan loop shared by --scan, --daemon and --ci.
 *
 * Fetches, extracts and diffs each not-yet-checked registry package with bounded
 * concurrency. Git trees + build.rs/source blobs are cached per owner/repo/tag.
 * Detects: BUILD_RS_INJECTED, BUILD_RS_MODIFIED, DEP_INJECTED,
 * SOURCE_MODIFIED, FILE_NOT_IN_GIT, BINARY_NOT_IN_GIT, CHECKSUM_MISMATCH,
 * YANKED, VERSION_REMOVED, CRATE_REMOVED.
 *
 * With opts.publishAge set, a separate PUBLISH_AGE lane runs off registry
 * metadata alone: it asks only how old the pinned version is, so it needs no
 * git side and still fires when one cannot be resolved.
 *
 * A second, cheap pass re-checks crates.io metadata (no tarball, no git tree)
 * for already-recorded packages still in the lockfile whose last metadata check
 * is older than 24h — so a version deleted AFTER we cleared it (the arrayref
 * pattern: malicious publish, 86 minutes online, then registry deletion) is
 * still reported. Disable with opts.recheck === false (--no-recheck).
 *
 * @param {object} opts
 * @param {string} [opts.lockPath]
 * @param {Array<{name,version}>} [opts.packages]
 * @param {import('better-sqlite3').Database} [opts.db]
 * @param {(msg:string)=>void} [opts.log]
 * @param {number} [opts.concurrency]
 * @param {Array} [opts.allowRules]  allowlist rules (from src/allowlist)
 * @param {boolean} [opts.recheck]  metadata re-check pass (default true)
 * @param {number} [opts.recheckMaxAgeMs]  staleness threshold (default 24h)
 * @param {{raw:string, ms:number, excludes:string[]}} [opts.publishAge]  when
 *        set (--min-publish-age), gate lockfile pins younger than `ms`. Absent
 *        by default, and absent means byte-identical 1.4.0 behaviour.
 * @returns {Promise<{newCount:number, suspicious:Array, results:Array,
 *   rechecked:Array, suppressedCount:number, publishAge:object|null}>}
 */
async function runScan(opts = {}) {
  const log = opts.log || (() => {});
  const db = opts.db; // a store (see src/store.js); required
  if (!db) throw new Error('runScan requires opts.db (a store instance)');
  const concurrency = Math.max(1, opts.concurrency || 5);
  const allowRules = opts.allowRules || [];

  const packages = (opts.packages || parseCargoLock(opts.lockPath || 'Cargo.lock', { withSource: true }))
    .map((p) => (p.source ? { ...p, cratesIo: isCratesIoSource(p.source) } : p));

  const seen = new Set();
  const todo = [];
  const all = [];
  const offRegistry = [];
  for (const p of packages) {
    const key = `${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // Only crates.io can be verified: there is no artifact to download and no
    // absence to read from a 404 the alternate registry never answered.
    if (p.cratesIo === false) { offRegistry.push(p); continue; }
    all.push(p);
    if (db.isChecked(p.name, p.version)) continue;
    todo.push(p);
  }

  log(`${packages.length} registry package(s) in lockfile, ${todo.length} not yet checked.`);
  if (offRegistry.length) {
    log(`${offRegistry.length} package(s) on another registry (not verifiable against crates.io):`);
  }
  for (const p of offRegistry) {
    log(`  [skipped] ${p.name}@${p.version} (${registryHost(p.source)})`);
  }

  const treeCache = new Map();
  const blobCache = new Map();
  const state = { gitRateLimited: false, suppressed: 0 };
  const publishAge = opts.publishAge || null;

  const results = await pool(todo, concurrency, (p) =>
    checkOne(p, { db, log, treeCache, blobCache, state, allowRules, publishAge }).catch((e) => {
      log(`  [error] ${p.name}@${p.version}: ${e.message}`);
      return { ...p, status: 'ERROR', error: e.message, flags: [] };
    })
  );

  const suspicious = results
    .filter((r) => r.status === 'SUSPICIOUS')
    .map((r) => ({ name: r.name, version: r.version, flags: r.flags }));
  const newCount = results.filter((r) => r.status !== 'ERROR').length;

  // Second pass: metadata-only re-check of already-cleared packages still in
  // the lockfile. Runs AFTER pass 1 so freshly-scanned rows (meta_checked_at =
  // now) are never re-fetched. Skipped when nothing is due (e.g. the Action's
  // fresh in-memory store).
  let rechecked = [];
  if (opts.recheck !== false) {
    const cutoff = Date.now() - (opts.recheckMaxAgeMs ?? RECHECK_MAX_AGE_MS);
    const due = db.getRecheckDue(all.filter((p) => p.cratesIo !== false), cutoff);
    if (due.length > 0) {
      log(`recheck: ${due.length} previously-checked package(s) due for a registry metadata re-check.`);
      rechecked = (await pool(due, concurrency, (row) =>
        recheckOne(row, { db, log, state, allowRules, publishAge }).catch((e) => {
          // Rate limit / outage: keep the previous verdict and leave the row
          // stale so the next run retries — never a removal finding.
          log(`  [recheck] ${row.name}@${row.version}: ${e.message} (kept previous verdict)`);
          return null;
        })
      )).filter(Boolean);
      for (const r of rechecked) {
        if (r.status === 'SUSPICIOUS' && r.previousStatus !== 'SUSPICIOUS') {
          suspicious.push({ name: r.name, version: r.version, flags: r.flags });
        }
      }
    }
  }

  db.recordRun({ new_count: newCount, suspicious_count: suspicious.length });

  return {
    newCount, suspicious, results, rechecked, suppressedCount: state.suppressed,
    publishAge: publishAge ? summarisePublishAge(publishAge, [...results, ...rechecked]) : null,
  };
}

/**
 * Roll the per-package evaluations up for the report section and --json.
 * Only packages the scan actually visited carry one: an already-checked pin is
 * skipped by pass 1, exactly as every other lane treats it.
 */
function summarisePublishAge(publishAge, results) {
  const buckets = { gated: [], unchecked: [], excluded: [], cleared: [] };
  const seen = new Set();
  for (const r of results) {
    const pa = r.publishAge;
    if (!pa || !buckets[pa.state]) continue;
    const key = `${r.name}@${r.version}`;
    if (seen.has(key)) continue; // a re-checked row supersedes nothing; count it once
    seen.add(key);
    buckets[pa.state].push({
      name: r.name, version: r.version, ...pa,
      // The emergency case: young AND already flagged by another lane.
      alsoFlagged: (r.flags || [])
        .filter((f) => f.flag !== 'PUBLISH_AGE' && severityOf(f) !== 'info')
        .map((f) => ({ flag: f.flag, file: f.file, severity: severityOf(f) })),
    });
  }
  return {
    threshold: publishAge.raw,
    thresholdMs: publishAge.ms,
    key: KEY,
    excludes: [...publishAge.excludes],
    gatedCount: buckets.gated.length,
    uncheckedCount: buckets.unchecked.length,
    excludedCount: buckets.excluded.length,
    clearedCount: buckets.cleared.length,
    gated: buckets.gated,
    unchecked: buckets.unchecked,
    excluded: buckets.excluded,
  };
}

/** Print a finding's detail indented and wrapped, so it stays readable at 80 columns. */
function logDetail(log, detail, width = 74) {
  for (const line of wrapText(detail, width)) log(`      ${line}`);
}

/** Host of a Cargo.lock `source` string, for the skipped-package note. */
function registryHost(source) {
  const m = String(source || '').match(/https?:\/\/([^/]+)/);
  return m ? m[1] : 'that registry';
}

/** Drop allowlisted flags, counting and logging what was muted. */
function suppress(ctx, name, version, flags) {
  const { kept, suppressed } = applyAllowlist(ctx.allowRules, name, version, flags);
  if (suppressed.length) {
    ctx.state.suppressed += suppressed.length;
    ctx.log(`  (suppressed ${suppressed.length} allowlisted finding(s) for ${name}@${version})`);
  }
  return kept;
}

/**
 * Registry-absence flag for a package whose version endpoint 404s. crates.io
 * deletes versions as its response to a malicious publish (arrayref@0.3.10,
 * internment@0.8.7, append-only-vec@0.1.9 on 2026-08-20), so absence of a
 * version the lockfile pins is a high-severity finding, not an error.
 */
function pushAbsenceFlag(flags, version, meta) {
  if (meta.crateExists) {
    pushFlag(flags, 'VERSION_REMOVED', null,
      `crates.io no longer serves this version; the crate exists but ${version} was removed ` +
      'from the registry. A deleted version is how crates.io responds to a malicious publish, ' +
      'so treat this as compromised until proven otherwise.');
  } else {
    pushFlag(flags, 'CRATE_REMOVED', null,
      'crates.io no longer serves this crate at all; the whole crate is unreachable ' +
      '(both the version and the crate itself return 404). Registry deletion is how crates.io ' +
      'responds to a malicious publish, so treat this as compromised until proven otherwise. ' +
      'If every crate reports this, suspect a proxy or captive portal answering 404s.');
  }
}

/**
 * Metadata-only re-check of one already-recorded package: one or two crates.io
 * API GETs, no tarball download, no git-tree fetch. Refreshes the
 * yanked/removed flags, carries the stored git-diff verdict, and persists
 * meta_checked_at so the next 24h of runs skip it.
 */
async function recheckOne(row, ctx) {
  const { db, log } = ctx;
  const meta = await fetchCrateMeta(row.name, row.version, { absent404: row.cratesIo !== false });
  const base = (row.flags || []).filter((f) => !META_FLAGS.has(typeof f === 'string' ? f : f.flag));
  const raw = [];
  let age = null;
  if (meta.absent) pushAbsenceFlag(raw, row.version, meta);
  else {
    if (meta.yanked) pushFlag(raw, 'YANKED', null);
    // PUBLISH_AGE is in META_FLAGS, so the stored one was just dropped from
    // `base`: recompute it here or a pin that has since aged out stays flagged
    // forever. With the gate off this run, dropping it is the right answer.
    if (ctx.publishAge) {
      age = gatePublishAge(row, meta, ctx);
      raw.push(...age.flags);
    }
  }

  const fresh = suppress(ctx, row.name, row.version, raw);
  const flags = [...base, ...fresh];
  const status = isSuspicious(flags) ? 'SUSPICIOUS' : (row.status === 'SUSPICIOUS' ? 'CLEAN' : row.status);
  db.recordMetaCheck({ name: row.name, version: row.version, status, flags });

  if (status === 'SUSPICIOUS' && row.status !== 'SUSPICIOUS') {
    const names = fresh.map((f) => f.flag).join(',');
    log(`  [SUSPICIOUS !!] ${row.name}@${row.version}${names ? ` {${names}}` : ''}`);
    for (const f of fresh) if (f.detail) logDetail(log, f.detail);
  } else if (status !== row.status) {
    log(`  [recheck] ${row.name}@${row.version}: ${row.status} -> ${status}`);
  }

  return {
    name: row.name, version: row.version, status, flags, previousStatus: row.status,
    publishAge: age ? age.publishAge : undefined,
  };
}

/**
 * Record a verdict reached from registry metadata alone — no artifact download,
 * no git tree. Both metadata-only outcomes share it: a version the registry no
 * longer serves, and a publish-age finding whose comparison lanes then failed.
 */
function recordMetaOnly(p, ctx, rawFlags, { note, details = true } = {}) {
  const { db, log } = ctx;
  const flags = suppress(ctx, p.name, p.version, rawFlags);
  const status = isSuspicious(flags) ? 'SUSPICIOUS' : 'CLEAN';
  db.recordPackage({ name: p.name, version: p.version, status, flags });
  const names = flags.map((f) => f.flag).join(',');
  log(`  [${status === 'SUSPICIOUS' ? 'SUSPICIOUS !!' : 'clean'}] ${p.name}@${p.version}` +
    `${names ? ` {${names}}` : ''}${note ? ` (${note})` : ''}`);
  if (details) for (const f of flags) if (f.detail) logDetail(log, f.detail);
  return { status, flags };
}

/**
 * Publish-age gate for one version, decided from registry metadata alone.
 *
 * Nothing here reads the artifact or the git side, which is the point: RFC 3923
 * asks only how old the version is, and each of the three arrayref-wave
 * versions was deleted well inside two hours, so any threshold at all sits them
 * out. Age is recomputed from the absolute `created_at` on every evaluation.
 */
function gatePublishAge(p, meta, ctx) {
  const { raw: threshold, ms, excludes } = ctx.publishAge;
  const base = { threshold, thresholdMs: ms, key: KEY, createdAt: meta.createdAt || null };

  if (isExcluded(excludes, p.name, p.version)) {
    return { flags: [], publishAge: { ...base, state: 'excluded', reason: 'exempted by --min-publish-age-exclude' } };
  }

  const ev = evaluatePublishAge(meta.createdAt, ms);
  const publishAge = { ...base, ...ev };
  if (ev.state !== 'gated') return { flags: [], publishAge };

  publishAge.clearsAt = new Date(ev.clearsAtMs).toISOString();
  const flags = [];
  pushFlag(flags, 'PUBLISH_AGE', null,
    `published ${formatStamp(ev.publishedMs)}, ${formatAge(ev.ageMs)} old; threshold ` +
    `${threshold} (${KEY}); clears ${formatStamp(ev.clearsAtMs)}. This says nothing about ` +
    'what the crate does. arrayref@0.3.10, internment@0.8.7 and append-only-vec@0.1.9 were ' +
    'each deleted within 107 minutes of publication.');
  return { flags, publishAge };
}

async function checkOne(p, ctx) {
  // Metadata first: a 404 here is the finding (crates.io deleted the version),
  // not an error — there is no artifact to download or diff. Only genuine
  // crates.io entries are probed; alternate registries keep the old throw.
  const meta = await fetchCrateMeta(p.name, p.version, { absent404: p.cratesIo !== false });
  if (meta.absent) {
    // A packument that 404s is VERSION_REMOVED / CRATE_REMOVED's finding and
    // carries no publish time; the age gate must not double-report it.
    const raw = [];
    pushAbsenceFlag(raw, p.version, meta);
    return { ...p, ...recordMetaOnly(p, ctx, raw) };
  }

  const age = ctx.publishAge ? gatePublishAge(p, meta, ctx) : null;
  try {
    return await compareArtifact(p, ctx, meta, age);
  } catch (e) {
    // The gate needed neither the artifact nor the git side, so a failure in
    // either must not swallow its finding.
    if (!age || age.flags.length === 0) throw e;
    return {
      ...p, error: e.message, publishAge: age.publishAge,
      ...recordMetaOnly(p, ctx, age.flags, { note: `comparison failed: ${e.message}`, details: false }),
    };
  }
}

async function compareArtifact(p, ctx, meta, age) {
  const { db, log, treeCache, blobCache, state } = ctx;
  const label = `${p.name}@${p.version}`;

  const crate = await fetchCrate(p.name, p.version, { meta });
  try {
    // Trusted Publishing (OIDC) attested record — strongest anchor, unforgeable.
    const tp = crate.trustpub;
    const attestedSha = tp && tp.sha ? tp.sha : undefined;
    const attestedRepo =
      tp && tp.provider === 'github' && tp.repository ? `https://github.com/${tp.repository}` : undefined;
    const vcsSha = crate.vcsInfo ? crate.vcsInfo.sha1 : undefined;

    // Git tree (cached per repo+commit — workspace siblings from the same commit
    // share it). Prefer attested commit, then self-reported vcs commit, then tags.
    let gt = { gitFiles: null, ref: null, owner: null, repo: null, host: null, viaCommit: false, refKind: null, provider: null };
    if (!state.gitRateLimited) {
      try {
        gt = await cachedGitTree(
          crate.repository, p.name, p.version,
          { vcsSha, attestedSha, attestedRepo }, treeCache
        );
      } catch (e) {
        if (e.rateLimited) {
          state.gitRateLimited = true;
          log(`  ! ${e.message}`);
          log('  ! Skipping git comparison for remaining crates this run.');
        } else throw e;
      }
    }

    // path_in_vcs from .cargo_vcs_info.json is authoritative when present.
    const diffOpts = crate.vcsInfo ? { knownPrefix: crate.vcsInfo.pathInVcs } : {};
    const result = diff(crate.crateFiles, gt.gitFiles, crate.prefix, diffOpts);
    // The age finding leads: it is already decided, and it is what a reader
    // needs first when it lands next to a divergence flag.
    let flags = [...(age ? age.flags : []), ...result.flags];

    // Manifest lane: dependency NAMES declared in the artifact's Cargo.toml but
    // absent from the git-side manifest (DEP_INJECTED — the arrayref@0.3.10
    // pattern). Only runs when the crate was confidently located in a full
    // tree; every unknown inside suppresses and records the reason.
    let manifest = null;
    if (!state.gitRateLimited && gt.provider && result.status !== 'NO_GIT_TAG') {
      try {
        const artifactToml = fs.readFileSync(
          path.join(crate.dir, `${p.name}-${p.version}`, 'Cargo.toml'), 'utf8');
        manifest = await diffManifests({
          name: p.name, artifactToml, gitFiles: gt.gitFiles, gitPrefix: result.gitPrefix,
          raw: (fp) => cachedBlob(gt, fp, blobCache),
        });
        flags.push(...manifest.flags);
      } catch (e) {
        if (e.rateLimited) state.gitRateLimited = true;
        manifest = { flags: [], skipped: e.rateLimited ? 'git host rate limited' : e.message };
      }
    }

    // TRUSTED_PUBLISH (info) — positive assurance; verified against attested sha.
    if (tp && tp.sha) pushFlag(flags, 'TRUSTED_PUBLISH', String(tp.sha).slice(0, 7));

    // VCS_MISMATCH (info) — self-reported publish commit disagrees with the
    // attested one. Advisory; the file diff (against the attested sha) is the
    // real guard, so this never alone marks the package suspicious.
    if (attestedSha && vcsSha && attestedSha !== vcsSha) {
      pushFlag(flags, 'VCS_MISMATCH', `${String(vcsSha).slice(0, 7)}!=${String(attestedSha).slice(0, 7)}`);
    }

    // CHECKSUM_MISMATCH — artifact does not match crates.io's recorded hash.
    if (crate.checksumOk === false) {
      pushFlag(flags, 'CHECKSUM_MISMATCH', `${p.name}-${p.version}.crate`);
    }

    // YANKED — advisory.
    if (crate.yanked) pushFlag(flags, 'YANKED', null);

    // Confirm content-diff suspects (build.rs + source .rs) with normalised
    // content, so line-ending noise never triggers a MODIFIED flag.
    if (!state.gitRateLimited && gt.provider && result.contentSuspects) {
      for (const s of result.contentSuspects) {
        try {
          const localPath = path.join(crate.dir, `${p.name}-${p.version}`, s.rel);
          const local = fs.readFileSync(localPath, 'utf8');
          const gitPath = result.gitPrefix ? `${result.gitPrefix}/${s.rel}` : s.rel;
          const remote = await cachedBlob(gt, gitPath, blobCache);
          if (remote != null && normalizeSource(remote) !== normalizeSource(local)) {
            pushFlag(flags, s.isBuildRs ? 'BUILD_RS_MODIFIED' : 'SOURCE_MODIFIED', s.rel);
          }
        } catch (e) {
          if (e.rateLimited) state.gitRateLimited = true;
          // else: leave unconfirmed (non-fatal)
        }
      }
    }

    flags = suppress(ctx, p.name, p.version, flags);

    // Status: SUSPICIOUS if any flag is >= medium severity; NO_GIT_TAG carries
    // through when we had no tree and produced no flags.
    let status;
    if (isSuspicious(flags)) status = 'SUSPICIOUS';
    else if (result.status === 'NO_GIT_TAG') status = 'NO_GIT_TAG';
    else status = 'CLEAN';

    db.recordPackage({ name: p.name, version: p.version, status, flags });

    const marker =
      status === 'SUSPICIOUS' ? 'SUSPICIOUS !!' :
      status === 'CLEAN' ? 'clean' : status.toLowerCase();
    const root = result.gitPrefix ? ` (git root: ${result.gitPrefix})` : '';
    const at = gt.viaCommit ? ` @${String(gt.ref).slice(0, 7)}${gt.refKind === 'attested' ? '✓' : ''}` : '';
    const hostTag = gt.host && gt.host !== 'github' ? ` [${gt.host}]` : '';
    const info = flags.filter((f) => severityOf(f) === 'info').map((f) => f.flag).join(',');
    log(`  [${marker}] ${label}${hostTag}${root}${at}${info ? ` {${info}}` : ''}`);

    return {
      ...p, status, flags, gitPrefix: result.gitPrefix, viaCommit: gt.viaCommit,
      ref: gt.ref, host: gt.host, refKind: gt.refKind,
      manifestSkipped: (manifest && manifest.skipped) || undefined,
      publishAge: age ? age.publishAge : undefined,
    };
  } finally {
    crate.cleanup();
  }
}

async function cachedGitTree(repository, name, version, opts, cache) {
  // Key by the strongest available commit (workspace siblings published from the
  // same release commit reuse one fetch); else by version.
  const anchor = opts.attestedSha || opts.vcsSha || 'v' + version;
  const preKey = `${opts.attestedRepo || repository}::${anchor}`;
  if (cache.has(preKey)) return cache.get(preKey);
  const gt = await fetchGitTree(repository, name, version, opts);
  cache.set(preKey, gt);
  return gt;
}

async function cachedBlob(gt, filePath, cache) {
  const key = `${gt.host}/${gt.owner}/${gt.repo}/${gt.ref}/${filePath}`;
  if (cache.has(key)) return cache.get(key);
  const content = await gt.provider.raw(gt.ref, filePath);
  cache.set(key, content);
  return content;
}

module.exports = { runScan };
