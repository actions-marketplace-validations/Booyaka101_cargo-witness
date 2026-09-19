'use strict';

/**
 * Endpoint base URLs. Overridable via env so the offline integration test can
 * point them at a local mock server. Trailing slashes are trimmed.
 *
 * GitHub uses a fixed API host (api.github.com). GitLab and Gitea/Forgejo derive
 * their base from the repository's own hostname (so self-hosted GitLab / any
 * Gitea instance works) unless an override is provided (used by tests).
 */
function trim(u) {
  return u == null ? u : String(u).replace(/\/+$/, '');
}

const config = {
  cratesApiBase: trim(process.env.CARGO_WITNESS_CRATES_API || 'https://crates.io/api/v1'),
  cratesStaticBase: trim(process.env.CARGO_WITNESS_CRATES_STATIC || 'https://static.crates.io'),

  githubApiBase: trim(process.env.CARGO_WITNESS_GITHUB_API || 'https://api.github.com'),
  githubRawBase: trim(process.env.CARGO_WITNESS_GITHUB_RAW || 'https://raw.githubusercontent.com'),

  // null → derive from the repository hostname; set (tests) → force this base.
  gitlabApiBase: trim(process.env.CARGO_WITNESS_GITLAB_API) || null,
  gitlabRawBase: trim(process.env.CARGO_WITNESS_GITLAB_RAW) || null,
  giteaApiBase: trim(process.env.CARGO_WITNESS_GITEA_API) || null,
  giteaRawBase: trim(process.env.CARGO_WITNESS_GITEA_RAW) || null,

  userAgent: 'cargo-witness/1.5 (github.com/Booyaka101/cargo-witness)',
};

module.exports = { config };
