'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const tar = require('tar');
const { config } = require('./config');
const { fetchRetry } = require('./util');

const UA = config.userAgent;

/**
 * STEP 3 — Crate fetcher.
 *
 * 1. GET crates.io API v1 for {name}/{version} → repository, checksum, yanked.
 *    NOTE: the version endpoint returns { version: {...} } with NO top-level
 *    `crate` object; repository lives at version.repository.
 * 2. Download the .crate from the static CDN. The API's `dl_path` is a
 *    crates.io redirect path (prefixing it onto static.crates.io 403s); use the
 *    direct pattern `{static}/crates/{name}/{name}-{version}.crate`.
 * 3. Verify sha256 against the API-recorded checksum.
 * 4. Extract; files land under `{name}-{version}/`.
 * 5. For each extracted file compute its git blob sha1 (so shared files can be
 *    content-compared with the git tree's blob shas — no extra network).
 *
 * The extracted directory is NOT deleted here — the caller reads file contents
 * for on-mismatch verification, then calls `cleanup()`.
 *
 * @returns {Promise<{
 *   repository:string|null, crateFiles:Map<string,string>, prefix:string,
 *   dir:string, cleanup:()=>void, checksumOk:boolean|null,
 *   checksum:string|null, yanked:boolean
 * }>}
 */
async function fetchCrate(name, version, { tmpRoot, meta } = {}) {
  if (!meta) meta = await fetchCrateMeta(name, version);
  if (meta.absent) {
    throw new Error(
      `crates.io no longer serves ${name}@${version} (removed from the registry); no artifact to download`
    );
  }
  const repository = meta.repository || null;

  const dir = fs.mkdtempSync(
    path.join(tmpRoot || os.tmpdir(), `cw-${sanitize(name)}-${sanitize(version)}-`)
  );
  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  };

  try {
    const cratePath = path.join(dir, `${name}-${version}.crate`);
    const staticUrl =
      `${config.cratesStaticBase}/crates/${encodeURIComponent(name)}/` +
      `${encodeURIComponent(name)}-${encodeURIComponent(version)}.crate`;
    await downloadTo(staticUrl, cratePath);

    let checksumOk = null;
    if (meta.checksum) {
      checksumOk = sha256File(cratePath).toLowerCase() === meta.checksum.toLowerCase();
    }

    await tar.extract({ file: cratePath, cwd: dir });

    const prefix = `${name}-${version}/`;
    const crateFiles = listFilesWithSha(dir, prefix);

    // .cargo_vcs_info.json (present in modern crates) records the EXACT commit
    // the artifact was published from, plus the crate's path within the repo.
    // This lets us verify against the precise commit instead of guessing a tag.
    const vcsInfo = readVcsInfo(path.join(dir, `${name}-${version}`, '.cargo_vcs_info.json'));

    return {
      repository,
      crateFiles,
      prefix,
      dir,
      cleanup,
      checksumOk,
      checksum: meta.checksum,
      yanked: meta.yanked,
      vcsInfo,
      trustpub: meta.trustpub,
    };
  } catch (e) {
    cleanup();
    throw e;
  }
}

/**
 * Fetch crates.io metadata for one version.
 *
 * A 404 on the version endpoint is a signal, not an error: crates.io responds
 * to a malicious publish by DELETING the version (arrayref@0.3.10, 2026-08-20).
 * With `absent404` (the default) a 404 returns a typed absence instead of
 * throwing, disambiguated by one extra GET on the crate itself:
 *   version 404 + crate 200 → { absent: true, crateExists: true }  (VERSION_REMOVED)
 *   version 404 + crate 404 → { absent: true, crateExists: false } (CRATE_REMOVED)
 * Every other non-ok status still throws — fetchRetry's backoff owns 429/5xx,
 * so an outage or rate limit can never masquerade as a removal.
 * Pass `absent404: false` for non-crates.io registry entries, where a 404 from
 * crates.io proves nothing.
 */
async function fetchCrateMeta(name, version, { absent404 = true } = {}) {
  const url = `${config.cratesApiBase}/crates/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
  const res = await fetchRetry(url);
  if (res.status === 404 && absent404) {
    const crateRes = await fetchRetry(`${config.cratesApiBase}/crates/${encodeURIComponent(name)}`);
    if (crateRes.ok) return { absent: true, crateExists: true };
    if (crateRes.status === 404) return { absent: true, crateExists: false };
    throw new Error(`crates.io API ${crateRes.status} for ${name}`);
  }
  if (!res.ok) throw new Error(`crates.io API ${res.status} for ${name}@${version}`);
  const data = await res.json();
  const v = data.version || {};
  const c = data.crate || {};
  return {
    dl_path: v.dl_path,
    repository: v.repository || c.repository || null,
    checksum: v.checksum || null,
    yanked: !!v.yanked,
    // Registry publish time (RFC 3923 calls it `pubtime`). Kept as the absolute
    // ISO timestamp the API returned so age is always recomputed at evaluation
    // time; a derived age cached in the store would go stale immediately.
    createdAt: v.created_at || null,
    // Trusted Publishing (OIDC) record set by crates.io — cannot be forged by
    // the publisher. { provider, repository, run_id, sha } or null.
    trustpub: v.trustpub_data || null,
  };
}

async function downloadTo(url, dest) {
  const res = await fetchRetry(url);
  if (!res.ok) throw new Error(`download ${res.status} for ${url}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

function sha256File(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

/** git blob object id: sha1("blob " + bytelen + "\0" + content). */
function gitBlobSha(buf) {
  const h = crypto.createHash('sha1');
  h.update(`blob ${buf.length}\0`);
  h.update(buf);
  return h.digest('hex');
}

function sanitize(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Read .cargo_vcs_info.json → { sha1, pathInVcs } or null.
 * Shape: { "git": { "sha1": "<commit>" }, "path_in_vcs": "<subdir>" }
 * `path_in_vcs` may be absent/"" for a crate at the repo root.
 */
function readVcsInfo(p) {
  let raw;
  try { raw = fs.readFileSync(p, 'utf8'); } catch { return null; }
  try {
    const j = JSON.parse(raw);
    const sha1 = j && j.git && typeof j.git.sha1 === 'string' ? j.git.sha1 : null;
    const pathInVcs = typeof j.path_in_vcs === 'string' ? j.path_in_vcs : '';
    if (!sha1) return null;
    return { sha1, pathInVcs };
  } catch {
    return null;
  }
}

/**
 * Recursively map every file under `root` starting with `prefix` to its git
 * blob sha. Paths are POSIX-style and keep the prefix.
 * @returns {Map<string,string>}
 */
function listFilesWithSha(root, prefix) {
  const out = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) {
        const rel = path.relative(root, abs).split(path.sep).join('/');
        if (rel.startsWith(prefix)) out.set(rel, gitBlobSha(fs.readFileSync(abs)));
      }
    }
  };
  walk(root);
  return out;
}

module.exports = { fetchCrate, fetchCrateMeta, gitBlobSha, UA };
