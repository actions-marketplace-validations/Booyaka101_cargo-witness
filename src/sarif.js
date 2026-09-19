'use strict';
const { severityOf } = require('./severity');

/**
 * Build a SARIF 2.1.0 log from suspicious findings, suitable for upload to
 * GitHub code scanning (github/codeql-action/upload-sarif).
 *
 * @param {Array<{name,version,flags}>} suspicious
 * @param {string} [lockPath]
 * @returns {object} SARIF log
 */
function toSarif(suspicious, lockPath = 'Cargo.lock') {
  const ruleIds = new Set();
  const results = [];

  for (const pkg of suspicious || []) {
    // A young pin is a warning on its own. A young pin on a crate that ALSO
    // trips a high flag is the emergency, so that result is raised to error.
    const withHigh = (pkg.flags || []).some((f) => severityOf(f) === 'high');
    for (const f of pkg.flags || []) {
      const flag = typeof f === 'string' ? f : f.flag;
      const file = typeof f === 'string' ? null : f.file;
      ruleIds.add(flag);
      results.push({
        ruleId: flag,
        level: flag === 'PUBLISH_AGE' && withHigh ? 'error' : sarifLevel(severityOf(f)),
        message: {
          text:
            `${pkg.name}@${pkg.version}: ${flag}` +
            (file ? ` (${file})` : '') +
            ' — ' +
            ((typeof f === 'object' && f.detail) || RULE_TEXT[flag] || 'published crate diverges from git source.'),
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: posix(lockPath) },
            },
            logicalLocations: [
              { fullyQualifiedName: `${pkg.name}@${pkg.version}`, kind: 'package' },
            ],
          },
        ],
        properties: { package: pkg.name, version: pkg.version, file: file || undefined },
      });
    }
  }

  const rules = [...ruleIds].map((id) => ({
    id,
    name: id,
    shortDescription: { text: RULE_TEXT[id] || id },
    defaultConfiguration: { level: sarifLevel(severityOf(id)) },
    helpUri: 'https://github.com/Booyaka101/cargo-witness#detections',
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'cargo-witness',
            informationUri: 'https://github.com/Booyaka101/cargo-witness',
            version: require('../package.json').version,
            rules,
          },
        },
        results,
      },
    ],
  };
}

const RULE_TEXT = {
  BUILD_RS_INJECTED: 'build.rs present in the published crate but absent from git.',
  DEP_INJECTED: 'A dependency declared in the published crate\'s manifest is absent from the git manifest.',
  BUILD_RS_MODIFIED: 'build.rs content differs between the published crate and git.',
  PUBLISH_AGE: "The lockfile pins a version younger than the configured minimum publish age; cargo's own resolver gate exempts versions already recorded in Cargo.lock.",
  SOURCE_MODIFIED: 'A Rust source file differs between the published crate and git.',
  FILE_NOT_IN_GIT: 'A Rust source file present in the artifact is absent from git.',
  BINARY_NOT_IN_GIT: 'A precompiled binary is shipped in the artifact but not in git.',
  CHECKSUM_MISMATCH: 'Artifact sha256 does not match the crates.io-recorded checksum.',
  VERSION_REMOVED: 'This version was deleted from crates.io while the crate still exists; deletion is how crates.io responds to a malicious publish.',
  CRATE_REMOVED: 'The crate is no longer served by crates.io at all; registry removal is how crates.io responds to a malicious publish.',
  VCS_MISMATCH: 'Self-reported publish commit differs from the attested (OIDC) commit.',
  TRUSTED_PUBLISH: 'Published via crates.io Trusted Publishing; verified against the attested commit.',
  YANKED: 'This crate version is yanked on crates.io.',
};

function sarifLevel(sev) {
  if (sev === 'high') return 'error';
  if (sev === 'medium') return 'warning';
  return 'note';
}

function posix(p) {
  return String(p).split('\\').join('/');
}

module.exports = { toSarif };
