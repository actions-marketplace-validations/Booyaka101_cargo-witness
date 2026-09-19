'use strict';
const { severityOf } = require('./severity');

/**
 * Publish-age gate — RFC 3923 vocabulary applied to a committed Cargo.lock.
 *
 * Cargo gates RESOLUTION from Rust 1.100 (rust-lang/cargo#17335): with
 * `resolver.incompatible-publish-age = "deny"` the resolver ignores versions
 * younger than `registry.global-min-publish-age` "unless they already exist in
 * the `Cargo.lock` file", and "once the versions are recorded in `Cargo.lock`,
 * subsequent resolves will keep them". A young version that is already pinned,
 * or that was forced through with `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`
 * (which #17335 says is "preserved within the lockfile"), is invisible to the
 * resolver from then on. That pinned half is what this gate reads.
 *
 * The gate detects nothing. It declines to go first.
 */

const KEY = 'registry.global-min-publish-age';

// cargo's own table (src/util/time_span.rs): singular and plural both accepted,
// a month is 2_629_746s (the average 30.436875 days), so one policy string
// parses the same here and in .cargo/config.toml.
const UNIT_SECONDS = {
  second: 1, seconds: 1,
  minute: 60, minutes: 60,
  hour: 60 * 60, hours: 60 * 60,
  day: 24 * 60 * 60, days: 24 * 60 * 60,
  week: 7 * 24 * 60 * 60, weeks: 7 * 24 * 60 * 60,
  month: 2629746, months: 2629746,
};

class DurationError extends Error {}

/**
 * Parse an RFC 3923 duration exactly as cargo's `maybe_parse_time_span` does:
 * ASCII digits, at most one separating space, then a unit word. No trimming —
 * `" 1 day"`, `"1 day "` and `"1  second"` are rejected by cargo, so they are
 * rejected here too. `"0"` is the documented "allow all packages" value.
 *
 * @param {string} raw
 * @returns {{ms:number, seconds:number, raw:string, count:number, unit:string|null}}
 * @throws {DurationError}
 */
function parseDuration(raw) {
  const s = String(raw);
  const bad = () => new DurationError(
    `invalid --min-publish-age ${JSON.stringify(s)}: expected an integer followed by ` +
    'seconds, minutes, hours, days, weeks or months (e.g. "24 hours", "7 days"), ' +
    'or "0" to disable.'
  );

  if (s === '0') return { ms: 0, seconds: 0, raw: s, count: 0, unit: null };

  const split = s.search(/[^0-9]/);
  if (split < 0) throw bad(); // all digits, no unit
  const digits = s.slice(0, split);
  let unit = s.slice(split);
  if (unit.startsWith(' ')) unit = unit.slice(1);

  const factor = UNIT_SECONDS[unit];
  if (digits === '' || factor === undefined) throw bad();

  const count = Number(digits);
  const seconds = count * factor;
  if (!Number.isSafeInteger(seconds)) throw bad();
  return { ms: seconds * 1000, seconds, raw: s, count, unit };
}

/**
 * Age of one version against the threshold, computed from the absolute
 * `created_at` at evaluation time (never from a stored derived age).
 *
 * A version with no publish time is `unchecked`, never gated: offline runs,
 * mirrors and alternate registries legitimately have none, and RFC 3923's own
 * applicability section exempts registries that do not set `pubtime`. Failing
 * those closed would make the gate unusable exactly where it is wanted.
 * A version exactly at the threshold has cleared it.
 *
 * @param {string|null} createdAt  ISO-8601 timestamp from crates.io `created_at`
 * @param {number} thresholdMs
 * @param {number} [now]
 */
function evaluatePublishAge(createdAt, thresholdMs, now = Date.now()) {
  if (createdAt == null || createdAt === '') {
    return { state: 'unchecked', reason: 'the registry reported no publish time for this version' };
  }
  const publishedMs = Date.parse(createdAt);
  if (Number.isNaN(publishedMs)) {
    return { state: 'unchecked', reason: `unreadable publish time ${JSON.stringify(String(createdAt))}` };
  }
  // Clamped: a publish time in the future (clock skew either side) is zero
  // seconds old, not negative. Without this, threshold "0" (the RFC's "allow
  // all packages") would gate a future-dated version instead of clearing it.
  const ageMs = Math.max(0, now - publishedMs);
  return {
    state: ageMs >= thresholdMs ? 'cleared' : 'gated',
    createdAt,
    publishedMs,
    ageMs,
    clearsAtMs: publishedMs + thresholdMs,
  };
}

/**
 * Exemptions, matched by bare name or by `name@version`. Used by
 * `--min-publish-age-exclude` and by the list round-tripped through
 * `.cargo/config.toml`.
 */
function isExcluded(excludes, name, version) {
  if (!excludes || excludes.length === 0) return false;
  return excludes.some((e) => e === name || e === `${name}@${version}`);
}

/**
 * True when every verdict-driving finding across these packages is a
 * publish-age one. The check has found no divergence in that case and must not
 * be summarised as if it had: a young version is not a compromised version.
 *
 * Info flags are ignored, because they never make a package suspicious in the
 * first place. TRUSTED_PUBLISH in particular is a positive assurance signal;
 * counting it would flip an attested-but-young crate back to reading like a
 * divergence finding.
 */
function isAgeOnly(packages) {
  const decisive = (p) => (p.flags || []).filter((f) => severityOf(f) !== 'info');
  const flagged = (packages || []).filter((p) => decisive(p).length > 0);
  if (flagged.length === 0) return false;
  return flagged.every((p) => decisive(p)
    .every((f) => (typeof f === 'string' ? f : f.flag) === 'PUBLISH_AGE'));
}

/** Compact age, e.g. `45s`, `40m`, `3h 12m`, `9d 4h`. */
function formatAge(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

/** `2026-09-08 08:32Z` — minute precision is all a publish-age report needs. */
function formatStamp(ms) {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}

module.exports = {
  KEY, DurationError, parseDuration, evaluatePublishAge, isExcluded, isAgeOnly,
  formatAge, formatStamp,
};
