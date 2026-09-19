# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-09-13

### Changed

- **`action.yml` now declares `runs.using: node24`.** GitHub removes the Node 20
  runtime from the Actions runners on **2026-09-23**, and the
  `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION` opt-out expires on the same day. An
  action still declaring `node20` does not launch after that: the runner cannot
  find the interpreter, so a consumer's `- uses: your-org/cargo-witness@v1` step
  fails before any of this code runs, with no fallback. Runners have defaulted
  to Node 24 since 2026-06-16, so this is a change of declaration, not of
  behaviour.

  No logic moved. The only change in `dist/action.js` is the version string
  `ncc` inlines from `package.json`, `1.5.0` to `1.6.0`. The rebuilt bundle was
  driven end to end on a real lockfile under both Node 20.20.2 and Node 24.21.0:
  stdout, stderr, the SARIF file, the `suspicious-count` / `suspicious` step
  outputs and the job summary all hash the same under each.

- **`npm run validate:action` keeps the validator but stops it vetoing the
  runtime.** `@action-validator/core` last published 0.6.0 on **2024-02-23** and
  compiles its schema into a wasm blob, so the `runs.using` enum it carries is
  `node12` / `node16` / `node20` and there is no newer copy to point it at. A
  2024 schema was deciding which 2026 runtime we ship.

  Deleting the check was the wrong fix, and patching a schema out of a wasm blob
  is not a thing to maintain. `scripts/validate-action.js` runs
  `@action-validator/cli` as before; if it fails, it re-validates the same file
  with `using` swapped for one the schema accepts. If that clears every error,
  the runtime string was the only objection and the file passes. Any other
  error, at any path, still fails the build, which is covered by a test that
  plants an unrelated schema violation and asserts a non-zero exit.

### Fixed

- **`engines.node` claimed `>=18`, which has not been true since the
  better-sqlite3 13 bump.** That dependency declares `engines.node >=22`, and on
  an older Node it does not throw, it segfaults: `--scan`, `--history` and
  `--daemon` die with exit 139 and an empty stderr, which reads as a phantom
  crash rather than as an unsupported Node. Reproduced here on Node 20.20.2 and
  clean on 24.21.0. The field now says `>=22` and a test fails if it ever drops
  below what a dependency needs again. `CONTRIBUTING.md` and `docs/LAUNCH.md`
  repeated the `18+` claim and now say 22. The Action itself is unaffected
  either way: `dist/action.js` contains no native module, which is why it runs
  on node24 at all.

### Added

- **`test/action-runtime.test.js`** asserts `runs.using` names a runtime GitHub
  still runs, and fails once the declared runtime is within 180 days of its
  removal date, not on the day it breaks. Setting `action.yml` back to `node20`
  turns this suite red today. The next runtime deadline arrives as a failing
  test rather than as a broken workflow.

- **README: runner requirements.** Node 24 needs macOS >= 13.5, and Node.js
  publishes no `linux-armv7l` build for 24 at all, so ARM32 self-hosted runners
  cannot run this action. Both are stated rather than glossed.

### Internal

- `action.yml` is now schema-checked on every pull request. Nothing validated it
  before. The test suite drives `scripts/validate-action.js` directly, so the
  check lives with the rest of the assertions rather than as a separate CI step
  that could only ever repeat them.

## [1.5.0] - 2026-09-08

### Added

- **Publish-age gate: `PUBLISH_AGE` (medium), opt-in via `--min-publish-age`.**
  The three arrayref-wave versions were online for 86, 90 and 107 minutes each,
  and `VERSION_REMOVED` only fires once crates.io has deleted them, which is by
  definition after the fact. `DEP_INJECTED` covers one shape of that attack, the
  added manifest line, and it needs a resolvable git side: 1.4.0 lists five
  conditions under which it honestly suppresses itself. This check covers all
  three of those compromises and every shape they could have taken, because it
  asks a different question. It asks how old the pinned version is. Any
  threshold at all sits a two-hour window out.

  It detects nothing. It declines to go first.

  `--min-publish-age "24 hours"` reads every `registry+` entry in the committed
  `Cargo.lock`, compares its crates.io `created_at` against the threshold, and
  flags each pin that is younger. The duration grammar is RFC 3923's, parsed
  exactly as cargo's own `time_span.rs` parses it (integer, at most one space,
  then `seconds`/`minutes`/`hours`/`days`/`weeks`/`months` singular or plural,
  a month being 2,629,746 seconds; `"0"` disables), so one policy string serves
  both cargo's resolver and this audit. The finding appears in the report, in
  `--json` (a per-package `publishAge` object plus a top-level threshold), in
  SARIF at level `warning`, in `--diff`, and in the desktop notification, and it
  is exemptible per crate with `--min-publish-age-exclude` (name or
  `name@version`) or through the existing allowlist.

- **`--write-cargo-config`** writes `registry.global-min-publish-age` into
  `.cargo/config.toml` line by line, so every other key, comment, blank line and
  the file's EOL style survive. Both spellings cargo accepts are handled, the
  `[registry]` table and a top-level dotted `registry.global-min-publish-age`,
  and whichever the file already uses is the one it keeps: TOML forbids mixing
  them, and appending a table next to a dotted key makes cargo refuse to load
  the config at all. It prints what the value was before it changes
  it and never overwrites in silence, and it reads the installed cargo rather
  than asserting anything about it: on a toolchain older than 1.100 it says the
  file is inert until you upgrade. Exemptions round-trip through a marker
  comment, because RFC 3923 defers a per-package exclude list to future work and
  cargo ships no key for one; inventing a key would make the file this tool just
  wrote a file cargo complains about. If the file already sets
  `resolver.incompatible-publish-age = "allow"`, which turns cargo's resolver
  gate off entirely, that is printed as a note and left alone.

### Changed

- **This changes verdicts only when you ask for it.** With `--min-publish-age`
  absent, output is byte-identical to 1.4.0, verified by diffing the full test
  run over every existing fixture, where all 144 lines match. Passing the flag
  is the only thing that can add an exit code, and a gated crate is `medium`, so
  it fails the default `--fail-on medium` gate.
- A crate that trips `PUBLISH_AGE` **and** a high or medium flag from another
  lane is reported as one entry saying both, not two unrelated findings. That
  combination is the emergency, and its SARIF result is raised from `warning`
  to `error`.
- The gate runs off registry metadata alone and is decided before any artifact
  download or git resolution, so it still fires when the git side cannot be
  resolved. Confirmed live on `tatara-kube@0.2.595`, which reports `NO_GIT_TAG`
  with the flag absent and `PUBLISH_AGE` with it set.
- Edge cases, each handled rather than guessed: a version with no `created_at`
  is reported `unchecked` and never blocked, because mirrors and alternate
  registries legitimately have none and RFC 3923's own applicability section
  exempts them; a version exactly at the threshold has cleared it; git and path
  dependencies never reach the gate, for the same reason the RFC exempts them;
  a crate whose whole packument 404s stays `VERSION_REMOVED`/`CRATE_REMOVED`'s
  finding and is not double-reported; an unparseable duration exits 2 naming the
  accepted units.

### Scope, accurately

Cargo does have this feature. `rust-lang/cargo#17335`, "feat(resolver):
Stabilize min-publish-age", merged 2026-08-28 for Rust 1.100, after
`-Zmin-publish-age` on nightly since 2026-06-21. What cargo gates is
**resolution**: with `resolver.incompatible-publish-age = "deny"` the resolver
"will ignore these versions unless they already exist in the `Cargo.lock`
file", and "once the versions are recorded in `Cargo.lock`, subsequent resolves
will keep them". A young version that is already pinned, or that was forced
through with `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`, which #17335's
own summary says is "preserved within the lockfile", is invisible to the
resolver from then on. The committed lockfile is the half this audits.

Note that the stabilized key set is `registry.global-min-publish-age`,
`registries.<name>.min-publish-age` and `resolver.incompatible-publish-age`.
The RFC's `registry.min-publish-age` did not ship; #17335 dropped it to avoid
confusion between `[registry]` and `[registries.crates-io]`.

Prior art: [cargo-cooldown](https://github.com/dertin/cargo-cooldown), a cargo
wrapper that "lets Cargo resolve the graph, then replaces fresh versions with
the newest older compatible versions". That is a different job on the other
side of the line. Its own README points CI and release automation at "plain
Cargo against committed `Cargo.lock` files", and those committed lockfiles are
what this reads. RFC 3923 is where the vocabulary comes from.

## [1.4.0] - 2026-08-30

### Added

- **Manifest lane: `DEP_INJECTED` (HIGH).** The August 20, 2026 arrayref
  compromise added exactly one line to the published manifest: a
  `[build-dependencies]` entry for the typosquat `proc-macro1`, whose build
  script downloads and executes a payload. The crate's own source was
  untouched, so no file diff fires, and `VERSION_REMOVED` only fires after
  crates.io deletes the version, which took up to 107 minutes. Until now the
  artifact-versus-git comparison named nothing inside that window, because
  `Cargo.toml` is deliberately on the byte-diff skip list (cargo rewrites it at
  package time). cargo-witness now parses the dependency names declared in the
  artifact's `Cargo.toml` across `[dependencies]`, `[build-dependencies]`,
  `[dev-dependencies]` and every `[target.<cfg>.*dependencies]` table,
  resolving `package = "..."` renames to the real crate name, parses the same
  set from the git-side manifest at the resolved commit and subdirectory,
  resolving `workspace = true` entries against the repository root's
  `[workspace.dependencies]`, and flags each crate name present in the
  artifact but absent from git as `DEP_INJECTED`. Names only, never version
  strings; version rewriting is exactly the normalisation that made the byte
  diff unusable. The flag is allowlist-suppressible per crate and per
  dependency name, appears in `--json`, `--report` and desktop notifications,
  and gets a SARIF rule at level `error`.
- Every unknown suppresses the flag rather than guessing: a truncated git
  tree, a manifest that fails to parse on either side, a git-side manifest
  that could not be fetched, an unresolvable workspace inheritance, or a crate
  that could not be confidently located in the tree. The reason is recorded,
  and `--diff <name> <version>` explains the suppression instead of staying
  silent. When the lane does compare, `--diff` prints both dependency-name
  sets side by side and marks the injected names.

### Changed

- **This changes verdicts.** A crate whose published manifest declares a
  dependency its git source never had was CLEAN under 1.3.0 and is SUSPICIOUS
  with a HIGH finding under 1.4.0, failing the default `--fail-on medium`
  gate. Measured against the resolved dependency sets of 617 real crates from
  three real lockfiles (a cargo workspace carrying serde, tokio and clap with
  heavy workspace inheritance at 42 crates, ripgrep at 52, and rust-lang/cargo
  itself at 523), the lane produced zero `DEP_INJECTED` findings on legitimate
  crates.
- The first measurement run did fire on four real crates, and both causes were
  mis-resolved git locations rather than parser bugs: `rand_core@0.9.5` fell
  back to the bare tag `0.9.5`, which in that repository belongs to the sibling
  `rand` crate, and three `varisat-*@0.2.2` crates published without a
  `path_in_vcs` resolved to a virtual workspace root that declares no
  dependencies at all. Rather than add an exception list, the lane now checks
  that the git-side manifest's `[package].name` is the crate being scanned, and
  suppresses with that reason when it is not. `im-rc` (whose repository
  manifest names the crate `im`) is caught by the same check.

## [1.3.0] - 2026-08-20

### Added

- **Registry-absence detection: `VERSION_REMOVED` and `CRATE_REMOVED` (both HIGH).**
  On 2026-08-20 the [Rust Security Response Team disclosed a supply chain attack
  on arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/):
  `arrayref@0.3.10` (86 minutes online), `internment@0.8.7` (90) and
  `append-only-vec@0.1.9` (107) were republished with a dependency on the
  typosquat `proc-macro1`, whose build script downloads and executes a payload
  at build time. crates.io responded by **deleting** the versions. cargo-witness
  1.2.1 saw that deletion as a plain fetch error: one `[error]` line, exit 0.
  Now a 404 from the version endpoint is treated as the signal it is, with one
  disambiguating request to the crate endpoint: crate still there means
  `VERSION_REMOVED`; crate gone entirely means `CRATE_REMOVED`. Both are
  allowlist-suppressible, appear in `--json`, `--report` and desktop
  notifications, and get SARIF rules at level `error`. Non-404 failures
  (outages, rate limits, 5xx) still retry and report as errors, never as
  findings, and alternate-registry lockfile entries are never probed.
- **24h metadata re-check of already-cleared packages.** The store (both the
  SQLite and in-memory backends) now records a `meta_checked_at` timestamp, and
  every scan runs a second, cheap pass over previously-recorded packages still
  in the lockfile whose metadata is older than 24 hours: crates.io metadata
  only, no tarball download, no git-tree fetch. A version that is yanked or
  deleted *after* cargo-witness cleared it flips to SUSPICIOUS on the next
  daemon run instead of staying silently green forever. Disable with
  `--no-recheck`. Rate limiting during the re-check keeps the previous verdict
  and retries next run.
- `--diff <name> <version>` on a withdrawn version now reports the removal and
  points at the local registry cache (`~/.cargo/registry/cache`), where the
  already-fetched `.crate` would still be, instead of failing on the download.

### Changed

- **This changes verdicts.** A lockfile pinning a withdrawn version that passed
  under 1.2.1 (exit 0 with an `[error]` line) now fails with a HIGH finding
  under the default `--fail-on medium`. That is the point of the release: on
  the machine that already fetched and executed the malicious build script,
  `cargo build` keeps working from the local cache and prints nothing.
- Scope note, to be accurate about what cargo already does: a cold build
  (empty registry cache) does fail when a locked version has vanished, but with
  a famously unhelpful error (rust-lang/cargo#10063, open since 2021) that
  never suggests the version was pulled as malicious. And RustSec closed the
  arrayref malware report (rustsec/advisory-db#3161) as not planned, so
  `cargo-audit` has no advisory to fire on for this incident. This detection is
  for the already-fetched, already-executed case, and for turning a silent
  exit-0 into a HIGH finding.

## [1.2.0] - 2026-07-25

### Added

- **Trusted Publishing verification.** Reads crates.io's `trustpub_data` (the
  OIDC-attested record of the CI run that published the crate — which the
  publisher cannot forge) and verifies against that **attested commit** in
  preference to any self-reported source. Adds `TRUSTED_PUBLISH` (info, a
  positive assurance signal) and `VCS_MISMATCH` (info) when the self-reported
  `.cargo_vcs_info.json` commit disagrees with the attested one.
- **Multi-host support.** Resolves and compares source on **GitHub, GitLab**
  (paginated tree API) **and Gitea/Forgejo/Codeberg**, in addition to GitHub —
  closing the coverage gap for the many crates hosted off GitHub. Per-host tokens
  (`GITLAB_TOKEN`, `GITEA_TOKEN`) raise rate limits; self-hosted instances are
  auto-detected from the repository hostname.
- **`--diff <name> <version>`** — an investigation view that resolves the source
  commit and prints a unified diff of any modified Rust source (especially
  `build.rs`) so a human can judge a finding.
- Launch materials and FAQ under `docs/`.

### Changed

- Ref-resolution priority is now: attested commit → `.cargo_vcs_info.json`
  commit → git tag. Git-host access is abstracted behind `src/hosts.js`.

## [1.1.0] - 2026-07-25

### Added

- **Exact-commit verification.** cargo-witness now reads `.cargo_vcs_info.json`
  from each `.crate` (present in modern crates) to obtain the precise `git.sha1`
  the artifact was published from and fetches the git tree at *that commit* —
  eliminating tag-guessing and its `NO_GIT_TAG` coverage gap. Verified crates
  show the short commit (`@abc1234`).
- **Authoritative subdirectory.** The crate's `path_in_vcs` is used directly as
  the workspace root instead of the heuristic resolver (still score-validated, so
  a mismatched repo/commit self-corrects to `NO_GIT_TAG`).

### Changed

- Git-tree cache is keyed by exact commit, so workspace siblings published from
  the same release commit (e.g. `serde` + `serde_derive`) share a single fetch.
- Tag-format guessing (`v{ver}` / `{ver}` / `{name}-{ver}` / `{name}-v{ver}`) is
  now the *fallback* for older crates without vcs info, or when the recorded
  commit is unreachable on the remote.

## [1.0.0] - 2026-07-25

### Added

- Initial public release of **cargo-witness**, a tool + daemon + GitHub Action
  that detects Rust supply-chain attacks by diffing published crate artifacts
  from `static.crates.io` against their git source.
- Artifact acquisition pipeline: downloads each crate's `.crate` archive from
  the CDN, extracts it, and fetches the matching git tag's file tree from GitHub
  for comparison.
- Detection flags, each with an associated severity:
  - `BUILD_RS_INJECTED` (HIGH) — a `build.rs` present in the published crate but
    absent from git source (the "onering" attack pattern).
  - `BUILD_RS_MODIFIED` (HIGH) — a `build.rs` present in both, but the published
    content differs from git.
  - `SOURCE_MODIFIED` (MEDIUM) — a non-`build.rs` source file whose published
    content differs from git, verified via git blob SHA and normalized content.
  - `FILE_NOT_IN_GIT` (MEDIUM) — a source file present in the artifact but absent
    from git.
  - `BINARY_NOT_IN_GIT` (HIGH) — a precompiled `.so`/`.dll`/`.exe`/`.dylib`/`.wasm`
    binary shipped only in the artifact.
  - `CHECKSUM_MISMATCH` (HIGH) — the artifact's computed sha256 does not match the
    crates.io-recorded checksum.
  - `YANKED` (INFO) — the version is yanked on crates.io.
- CLI with four modes: `--scan`, `--daemon`, `--report`, and `--ci`.
- CLI options: `--lock <path>`, `--concurrency <n>`, `--db <path>`, `--json`,
  `--now`, `--quiet`, `--fail-on <high|medium|info>`, `--sarif <path>`,
  `--history`, and `--version`.
- Environment configuration: `GITHUB_TOKEN` (raises the GitHub API rate limit)
  and `CARGO_WITNESS_NO_NOTIFY` (disables desktop notifications).
- GitHub Action packaged for `node20`, emitting a job summary and the
  `suspicious-count` and `suspicious` step outputs, plus `fail-on`, `sarif` and
  `config` inputs. The action bundle is **native-free** (uses an in-memory store,
  so no platform-specific `better-sqlite3` binary is committed to `dist/`).
- SARIF 2.1.0 output (`--sarif <path>` / action `sarif` input) for code scanning.
- Allowlist-based suppression of known-benign findings via `.cargo-witness.json`
  (or `--config <path>`).
- `--fail-on <high|medium|info>` severity gate for `--scan` and `--ci`.
- Resilient networking with retry and exponential backoff.
- Bounded concurrency for artifact downloads and comparisons.
- Git-tree caching to avoid redundant GitHub API calls.
- Checksum verification of downloaded artifacts against crates.io.
- Workspace-subdirectory resolution to locate a crate's source within a
  multi-crate repository.

[1.5.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.5.0
[1.4.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.4.0
[1.3.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.3.0
[1.2.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.2.0
[1.1.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.1.0
[1.0.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.0.0
