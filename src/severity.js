'use strict';

/**
 * Severity for each finding flag. Drives report colouring, --fail-on gating and
 * SARIF `level`.
 *   high   → strong tamper signal (build.rs / binary / checksum / registry removal)
 *   medium → source divergence from git (content or unexpected file), or a
 *            lockfile pin younger than the configured publish-age threshold
 *   info   → advisory (yanked)
 */
const SEVERITY = {
  CHECKSUM_MISMATCH: 'high',
  BUILD_RS_INJECTED: 'high',
  DEP_INJECTED: 'high',      // dependency in the artifact manifest, absent from git (arrayref 0.3.10)
  BUILD_RS_MODIFIED: 'high',
  BINARY_NOT_IN_GIT: 'high',
  VERSION_REMOVED: 'high',   // crates.io deleted this version (the arrayref response)
  CRATE_REMOVED: 'high',     // crates.io no longer serves the crate at all
  SOURCE_MODIFIED: 'medium',
  FILE_NOT_IN_GIT: 'medium',
  PUBLISH_AGE: 'medium',     // pinned version younger than the configured threshold
  VCS_MISMATCH: 'info',      // self-reported commit ≠ attested commit
  TRUSTED_PUBLISH: 'info',   // positive: published via OIDC Trusted Publishing
  YANKED: 'info',
};

const RANK = { info: 0, medium: 1, high: 2 };

function severityOf(flag) {
  const name = typeof flag === 'string' ? flag : flag.flag;
  return SEVERITY[name] || 'medium';
}

/** Highest severity among a list of flags, or null if none. */
function maxSeverity(flags) {
  let best = null;
  for (const f of flags || []) {
    const s = severityOf(f);
    if (best === null || RANK[s] > RANK[best]) best = s;
  }
  return best;
}

/** True if `sev` meets or exceeds the `threshold` (e.g. gate at 'medium'). */
function atLeast(sev, threshold) {
  if (!sev) return false;
  return RANK[sev] >= RANK[threshold];
}

/**
 * A finding is "suspicious" (recorded status SUSPICIOUS) if it has any flag of
 * severity >= medium. Info-only findings (e.g. YANKED alone) stay CLEAN but the
 * flag is still recorded and surfaced.
 */
function isSuspicious(flags) {
  return atLeast(maxSeverity(flags), 'medium');
}

module.exports = { SEVERITY, RANK, severityOf, maxSeverity, atLeast, isSuspicious };
